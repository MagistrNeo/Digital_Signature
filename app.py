from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
import os
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from pyhanko.sign import signers
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
#import win32com.client as win32
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from asn1crypto import cms

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_keys(private_key, public_key, data, private_key_file='private_key.pem', public_key_file='public_key.pem'):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, data[0]),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, data[1]),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, data[2]),
        x509.NameAttribute(NameOID.COMMON_NAME, data[3]),
        x509.NameAttribute(NameOID.SURNAME, data[4]),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=data[5]) 
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(
        private_key, hashes.SHA256()
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    with open(private_key_file, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("cert.pem", "wb") as f:
        f.write(cert_pem)    
    with open(public_key_file, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_private_key(private_key_file='private_key.pem'):
    """Загрузка приватного ключа из файла"""
    with open(private_key_file, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def load_public_key(public_key_file='public_key.pem'):
    """Загрузка публичного ключа из файла"""
    with open(public_key_file, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return public_key

def sign_file(file_path, private_key, signature_file=None, flag=True):
    if signature_file is None:
        signature_file = file_path + '.sig'
    
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    private_key = load_private_key()
    signature = private_key.sign(
        file_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    if flag:
        with open(signature_file, 'wb') as f:
            f.write(signature)
    
    return signature

def sign_word_with_cryptopro(doc_path):
    p = os.path.abspath(doc_path)
    if 'docx' in doc_path:
        word = win32.Dispatch("Word.Application")
        word.Visible = True
        doc = word.Documents.Open(p)
        signatures = doc.Signatures
        signature = signatures.Add()
    elif 'pdf' in doc_path:
        try:
            cms_signer = signers.SimpleSigner.load(
                'private_key.pem',
                'cert.pem',
                ca_chain_files=('cert.pem',),
                key_passphrase=None
            )
            
            if cms_signer is None:
                print(cms_signer)
                raise ValueError("Не удалось создать подписанта. Проверьте ключ, сертификат и пароль.")
        
            with open('test.pdf', 'rb') as doc:
                w = IncrementalPdfFileWriter(doc, strict=False)
                out = signers.sign_pdf(
                    w,
                    signers.PdfSignatureMetadata(field_name='Signature1'),
                    signer=cms_signer
                )
                with open('signed.pdf', 'wb') as f:
                    f.write(out.getbuffer())
            print("Документ успешно подписан!")
        except Exception as e:
            print(f"Ошибка: {e}")        
        
def create_p7s_document(data_file):
    # 1. Загружаем исходный файл
    with open(data_file, "rb") as f:
        original_data = f.read()

    # 2. Загружаем закрытый ключ
    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

    # 3. Загружаем сертификат
    with open("cert.pem", "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    # 4. Создаём подпись в формате PKCS#7
    signed_data = pkcs7.PKCS7SignatureBuilder(
        data=original_data,
        signers=[
            (
                cert,
                private_key,
                hashes.SHA256(),padding.PKCS1v15()  # Алгоритм хеширования (можно GOST)
            )
        ]
    ).sign(serialization.Encoding.DER, options=[pkcs7.PKCS7Options.Binary])

    # 5. Сохраняем подпись в файл .p7s
    with open(data_file + '.p7s', "wb") as f:
        f.write(signed_data)

def generate(data):
    private_key, public_key = generate_key_pair()
    save_keys(private_key, public_key, data)    

def verify_signature(file_path, signature_file, public_key_path):
    # Загрузка данных
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    with open(signature_file, 'rb') as f:
        signature = f.read()
    
    # Загрузка открытого ключа
    with open(public_key_path, 'rb') as f:
        public_key = load_pem_public_key(f.read())
    
    # Проверка подписи
    try:
        public_key.verify(
            signature,
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True  # Подпись верна
    except Exception as e:
        return False  # Подпись недействительна

def extract_from_p7s(p7s_file: str, output_file: str):
    """
    Извлекает исходный файл из подписи .p7s
    """
    with open(p7s_file, "rb") as f:
        p7s_data = f.read()
    
    # Парсинг структуры CMS
    signed_data = cms.ContentInfo.load(p7s_data)
    if signed_data["content_type"].native != "signed_data":
        raise ValueError("Неверный формат подписи")
    
    # Извлечение содержимого
    encap_content = signed_data["content"]["encap_content_info"]
    if encap_content["content_type"].native != "data":
        raise ValueError("Контейнер не содержит данных")
    
    # Сохранение извлеченного файла
    with open(output_file, "wb") as f:
        f.write(encap_content["content"].native)
    

def main():
    import sys
    
    if len(sys.argv) < 2:
        print("Использование: python sign_file.py <файл> [private_key.pem]")
        return

# Пример использования:
    file_path = sys.argv[1]
    key_file = sys.argv[2] if len(sys.argv) > 2 else 'private_key.pem'
    if not os.path.exists(file_path):
        print(f"Файл {file_path} не существует!")
        return
    
    if not os.path.exists(key_file):
        print(f"Приватный ключ {key_file} не найден. Создаем новую пару ключей...")
        private_key, public_key = generate_key_pair()
        save_keys(private_key, public_key)
        print(f"Созданы новые ключи: private_key.pem и public_key.pem")
    else:
        private_key = load_private_key(key_file)
    
    print(f"Подписываем файл {file_path}...")
    signature = sign_file(file_path, private_key)
    print(f"Файл успешно подписан. Подпись сохранена в {file_path}.sig")
    print("Файл теперь доступен только для чтения.")

if __name__ == "__main__":       
   print(dir(NameOID))
