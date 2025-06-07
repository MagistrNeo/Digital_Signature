import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.font import Font
from app import load_private_key, sign_file, load_public_key
from app import sign_word_with_cryptopro, create_p7s_document, generate
from app import verify_signature, extract_from_p7s
import os

class FileSignerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("FileSigner Pro")
        self.root.geometry("540x400")
        self.root.resizable(False, False)
        self.bg_color = "#023e8a"
        self.button_color = "#E9B869"
        self.setup_ui()

    def setup_ui(self):
        # Стили
        self.style = ttk.Style()
        # Изменяем стиль обычных кнопок на красный
        self.style.theme_use("clam")
        self.style.configure('TButton', 
                           font=('Helvetica', 10), 
                           padding=6,
                           background=self.button_color, relief='flat',  
                           foreground='black', focuscolor = '')  # Белый текст
        self.style.configure('TRadiobutton', background = self.bg_color, foreground = '#fefae0', relief = 'flat', focuscolor = '')
        self.style.map('TRadiobutton', background=[('active','#023e8a')])
        self.style.configure('TLabel', background = self.bg_color, foreground = '#fefae0', font=('Helvetica', 10))
        self.style.configure('Header.TLabel', font=('Helvetica', 14, 'bold'))
        
        # Цветовая схема
        self.root.configure(bg=self.bg_color)
        
        # Заголовок
        header_frame = tk.Frame(self.root, bg=self.bg_color)
        header_frame.pack(pady=10)
        
        tk.Label(header_frame, 
                text="FileSigner Pro", 
                font=('Helvetica', 18, 'bold'), 
                bg=self.bg_color, fg="#fefae0").pack()
        
        # Основное содержимое
        content_frame = tk.Frame(self.root, bg=self.bg_color)
        content_frame.pack(pady=20, padx=20, fill='x', expand=True)
        
        # Поле выбора файла
        file_frame = tk.Frame(content_frame, bg=self.bg_color)
        file_frame.pack(fill='x', pady=5)
        
        tk.Label(file_frame, 
                text="Выберите файл для подписи:", 
                bg=self.bg_color, fg="#fefae0").pack(anchor='w')
        
        self.entry_file = ttk.Entry(file_frame, width=40)
        self.entry_file.pack(side='left', padx=(0, 5))
        
        ttk.Button(file_frame, 
                  text="Обзор...", 
                  command=self.select_file).pack(side='left')
        
        # Опции подписи
        options_frame = tk.Frame(content_frame, bg=self.bg_color)
        options_frame.pack(fill='x', pady=10)
        
        tk.Label(options_frame, 
                text="Тип подписи:", 
                bg=self.bg_color, fg="#fefae0").pack(anchor='w')
        
        self.sign_type = tk.StringVar(value="detached")
        ttk.Radiobutton(options_frame, 
                        text="Откреплённая", 
                        variable=self.sign_type,
                        value="detached", style='TRadiobutton').pack(anchor='w')
        ttk.Radiobutton(options_frame, 
                        text="Встроенная", 
                        variable=self.sign_type, 
                        value="embedded", style='TRadiobutton').pack(anchor='w')
        ttk.Radiobutton(options_frame, 
                        text="Присоединённая", 
                        variable=self.sign_type, 
                        value="attached", style='TRadiobutton').pack(anchor='w')        
        
        # Горизонтальный фрейм для кнопок действий
        action_buttons_frame = tk.Frame(content_frame, bg=self.bg_color)
        action_buttons_frame.pack(fill='x', pady = 10)
        
        # Кнопки действий в одну строку
        ttk.Button(action_buttons_frame, 
                  text="Создать ключи",
                  command=self.generate_gui,
                  style='TButton').pack(side=tk.LEFT, padx=5)
        
        ttk.Button(action_buttons_frame, 
                  text="Проверить ОЭП",
                  command=self.open_file_dialogs,
                  style='TButton').pack(side=tk.LEFT, padx=5)
        
        ttk.Button(action_buttons_frame, 
                  text="Извлечь данные",
                  command=self.open_file_dialogs_to_unpack,
                  style='TButton').pack(side=tk.LEFT, padx=5)
        
        ttk.Button(action_buttons_frame, 
                  text="Подписать файл",
                  command=self.sign_file_gui,
                  style='TButton').pack(side=tk.LEFT, padx=5)        
        
        # Статус бар
        self.status_bar = tk.Label(self.root, 
                                 text="Готов к работе", 
                                 bd=1, relief=tk.SUNKEN, 
                                 anchor=tk.W,
                                 bg=self.bg_color,
                                 fg='#fefae0')
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
            
    def select_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.entry_file.delete(0, tk.END)
            self.entry_file.insert(0, file_path)
            self.status_bar.config(text=f"Выбран файл: {os.path.basename(file_path)}")
        
    def generate_gui(self):
        self.status_bar.config(text="Генерация ключей...")
        self.root.update()
        self.show_cert_dialog()
        
    def open_file_dialogs(self):
        file_dialog_window = tk.Toplevel(root)
        file_dialog_window.title("Выбор файлов")
        file_dialog_window.geometry("420x250")
        file_dialog_window.configure(bg = self.bg_color)
        file_dialog_window.resizable(False, False)
        file_dialog_window.grab_set()        
    
        def select_file(entry_widget):
            file_path = filedialog.askopenfilename(title="Выберите файл")
            if file_path:
                entry_widget.delete(0, tk.END)
                entry_widget.insert(0, file_path)
    
        # Виджеты для файла 1
        frame_file1 = tk.Frame(file_dialog_window, bg = self.bg_color, padx = 20)
        frame_file1.pack(pady=5, fill=tk.X)
        ttk.Label(frame_file1, text="Подписанный файл:").pack(anchor = "w")
        self.entry_file1 = tk.Entry(frame_file1, width=40)
        self.entry_file1.pack(side=tk.LEFT, padx=5)
        ttk.Button(frame_file1, text="Обзор...", command=lambda: select_file(self.entry_file1)).pack(side=tk.LEFT)
    
        # Виджеты для файла 2
        frame_file2 = tk.Frame(file_dialog_window, bg = self.bg_color, padx = 20)
        frame_file2.pack(pady=5, fill=tk.X)
        ttk.Label(frame_file2, text="ОЭП:").pack(anchor = "w")
        self.entry_file2 = tk.Entry(frame_file2, width=40)
        self.entry_file2.pack(side=tk.LEFT, padx=5)
        ttk.Button(frame_file2, text="Обзор...", command=lambda: select_file(self.entry_file2)).pack(side=tk.LEFT)
    
        # Виджеты для файла 3
        frame_file3 = tk.Frame(file_dialog_window, bg = self.bg_color, padx = 20)
        frame_file3.pack(pady=5, fill=tk.X)
        ttk.Label(frame_file3, text="Открытый ключ:").pack(anchor = "w")
        self.entry_file3 = tk.Entry(frame_file3, width=40)
        self.entry_file3.pack(side=tk.LEFT, padx=5)
        ttk.Button(frame_file3, text="Обзор...", command=lambda: select_file(self.entry_file3)).pack(side=tk.LEFT)
    
        # Кнопка "Готово" (опционально)
        btn_done = ttk.Button(file_dialog_window, text="Проверить", 
                              command= lambda: self.check_signature(self.entry_file1.get(), self.entry_file2.get(), self.entry_file3.get()))
        btn_done.pack(pady=10)
    
        
    def open_file_dialogs_to_unpack(self):
        file_dialog_window = tk.Toplevel(root)
        file_dialog_window.title("Выбор файлов")
        file_dialog_window.geometry("420x200")
        file_dialog_window.configure(bg = self.bg_color)
        file_dialog_window.resizable(False, False)
        file_dialog_window.grab_set()        
    
        def select_file(entry_widget):
            file_path = filedialog.askopenfilename(title="Выберите файл")
            if file_path:
                entry_widget.delete(0, tk.END)
                entry_widget.insert(0, file_path)
    
        # Виджеты для файла 1
        frame_file1 = tk.Frame(file_dialog_window, bg = self.bg_color, padx = 20)
        frame_file1.pack(pady=5, fill=tk.X)
        ttk.Label(frame_file1, text="Контейнер p7s:").pack(anchor = "w")
        self.entry_file1 = tk.Entry(frame_file1, width=40)
        self.entry_file1.pack(side=tk.LEFT, padx=5)
        ttk.Button(frame_file1, text="Обзор...", command=lambda: select_file(self.entry_file1)).pack(side=tk.LEFT)
    
        # Виджеты для файла 2
        frame_file2 = tk.Frame(file_dialog_window, bg = self.bg_color, padx = 20)
        frame_file2.pack(pady=5, fill=tk.X)
        ttk.Label(frame_file2, text="Файл для приёма данных:").pack(anchor = "w")
        self.entry_file2 = tk.Entry(frame_file2, width=40)
        self.entry_file2.pack(side=tk.LEFT, padx=5)
        ttk.Button(frame_file2, text="Обзор...", command=lambda: select_file(self.entry_file2)).pack(side=tk.LEFT)
    
        # Кнопка "Готово" (опционально)
        btn_done = ttk.Button(file_dialog_window, text="Извлечь", 
                              command= lambda: self.extract_bar(self.entry_file1.get(), self.entry_file2.get()))
        btn_done.pack(pady=10)
    def extract_bar(self, p7s_path, file_path):
        extract_from_p7s(p7s_path, file_path)
        messagebox.showinfo("Успех", "Данные успешно извлечены!")
        self.status_bar.config(text="Данные успешно извлечены")
    def check_signature(self, file_path, signature_file, public_key_path):
        if verify_signature(file_path, signature_file, public_key_path):
            messagebox.showinfo("Проверка окончена", "Подпись действительна! Файл не был изменён!")
            self.status_bar.config(text="Подпись действительна! Файл не был изменён")
        else:
            messagebox.showinfo("Проверка окончена", "Подпись недействительна! Файл был изменён!")
            self.status_bar.config(text="Подпись недействительна! Файл был изменён")
            
    def show_cert_dialog(self):
        """Окно настроек генерации сертификата"""
        dialog = tk.Toplevel(self.root)
        color = "#023e8a"
        dialog.title("Параметры сертификата")
        dialog.geometry("400x400")
        dialog.configure(bg=color)
        dialog.resizable(False, False)
        dialog.grab_set()  # Блокирует главное окно
        
        # Переменные для хранения параметров
        self.country_var = tk.StringVar(value="Ru",)
        self.prov_var = tk.StringVar(value="Moscow")
        self.local_var = tk.StringVar(value="Moscow")
        self.org_var = tk.StringVar(value="My Company")
        self.name_var = tk.StringVar(value="Name")
        self.surname_var = tk.StringVar(value="Surname")
        self.time_var = tk.IntVar(value=365)
        
        # Элементы формы
        ttk.Label(dialog, text="Страна (2 буквы):").pack(pady=5)
        ttk.Entry(dialog, textvariable=self.country_var).pack()
        
        ttk.Label(dialog, text="Город регистрации:").pack(pady=5)
        ttk.Entry(dialog, textvariable=self.local_var).pack() 
        
        ttk.Label(dialog, text="Наименование организации:").pack(pady=5)
        ttk.Entry(dialog, textvariable=self.org_var).pack()
        
        ttk.Label(dialog, text="Имя владельца сертификата:").pack(pady=5)
        ttk.Entry(dialog, textvariable=self.name_var).pack()        
        
        ttk.Label(dialog, text="Фамилия владельца сертификата:").pack(pady=5)
        ttk.Entry(dialog, textvariable=self.surname_var).pack()
        
        ttk.Label(dialog, text="Срок действия (дни):").pack(pady=5)
        ttk.Entry(dialog, textvariable=self.time_var).pack()        
        
        ttk.Button(dialog, 
                  text="Сгенерировать", 
                  command=lambda: self.generate_with_params(dialog)).pack(pady=20)    
        return dialog
    
    def generate_with_params(self, dialog):
        try:
            data = (self.country_var.get(), self.local_var.get(), 
                    self.org_var.get(), self.name_var.get(), self.surname_var.get(), self.time_var.get())
            generate(data)
            messagebox.showinfo("Успех", "Сертификат и ключи успешно созданы!")
            self.status_bar.config(text="Сертификат и ключи успешно созданы")            
            dialog.destroy()
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка генерации:\n{str(e)}")
            
    def sign_file_gui(self):
        file_path = self.entry_file.get()
        if not file_path:
            messagebox.showerror("Ошибка", "Выберите файл для подписи!")
            return
            
        try:
            self.status_bar.config(text="Подписание файла...")
            self.root.update()
            
            private_key = load_private_key()

            if self.sign_type.get() == 'detached':
                sign_file(file_path, private_key)
            elif self.sign_type.get() == 'embedded':
                sign_word_with_cryptopro(file_path)
            else:
                create_p7s_document(file_path)
            messagebox.showinfo("Успех", 
                              "Файл успешно подписан!\n" + 
                              "Цифровая подпись защищает документ от изменений.")
            self.status_bar.config(text="Файл успешно подписан")
            
        except Exception as e:
            messagebox.showerror("Ошибка", 
                               f"Не удалось подписать файл:\n{str(e)}")
            self.status_bar.config(text="Ошибка при подписании файла")
        

if __name__ == "__main__":
    root = tk.Tk()
    app = FileSignerApp(root)
    root.mainloop()