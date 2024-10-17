import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk, ImageDraw
import bcrypt
import os
import sys

# Función para obtener la ruta del directorio
def resource_path(relative_path):
    """Obtiene la ruta absoluta al recurso, funciona tanto en desarrollo como en el ejecutable."""
    try:
        # PyInstaller crea una carpeta temporal y guarda el path en _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

# Carga la imagen y el archivo de contraseñas usando la función resource_path
image_path = resource_path("zomBits.png")
passwords_file_path = resource_path("passwords.txt")

# Función para añadir la funcionalidad de almacenamiento de contraseñas
def add_password():
    password = password_entry.get().encode('utf-8')  
    site = site_entry.get()
    
    if password and site:
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8') 
        
        with open(passwords_file_path, "a") as file:
            file.write(f"Sitio: {site}, Contraseña cifrada: {hashed_password}\n")
        
        messagebox.showinfo("Éxito", f"Contraseña guardada para {site}")
        site_entry.delete(0, tk.END)
        password_entry.delete(0, tk.END)
        load_passwords()  
    else:
        messagebox.showerror("Error", "Por favor, introduce todos los campos.")

def verify_password():
    site = site_entry.get()
    input_password = password_entry.get().encode('utf-8')  

    if site and input_password:
        try:
            with open(passwords_file_path, "r") as file:
                for line in file:
                    if line.startswith(f"Sitio: {site}"):
                        hashed_password = line.split(", Contraseña cifrada: ")[1].strip()
                        if bcrypt.checkpw(input_password, hashed_password.encode('utf-8')):
                            messagebox.showinfo("Éxito", "La contraseña es correcta.")
                        else:
                            messagebox.showerror("Error", "La contraseña es incorrecta.")
                        return
                messagebox.showerror("Error", f"No se encontró ninguna contraseña guardada para {site}.")
        except FileNotFoundError:
            messagebox.showerror("Error", "No hay contraseñas guardadas.")
    else:
        messagebox.showerror("Error", "Por favor, introduce todos los campos.")

def load_passwords():
    password_list.delete(0, tk.END)  
    try:
        with open(passwords_file_path, "r") as file:
            for line in file:
                password_list.insert(tk.END, line.strip())
    except FileNotFoundError:
        pass 

def edit_password():
    selected = password_list.curselection()  
    if selected:
        site_info = password_list.get(selected)
        site, hashed_password = site_info.split(", Contraseña cifrada: ")
        site_entry.delete(0, tk.END)
        site_entry.insert(0, site.split(": ")[1])  
        password_entry.delete(0, tk.END)  
        messagebox.showinfo("Edición", "Modifica la contraseña y guarda los cambios.")
        delete_password()  

def delete_password():
    selected = password_list.curselection()  
    if selected:
        site_info = password_list.get(selected)
        site = site_info.split(",")[0].split(": ")[1]
        with open(passwords_file_path, "r") as file:
            lines = file.readlines()
        with open(passwords_file_path, "w") as file:
            for line in lines:
                if not line.startswith(f"Sitio: {site}"):
                    file.write(line)
        messagebox.showinfo("Eliminación", "Contraseña eliminada con éxito.")
        load_passwords()  
    else:
        messagebox.showerror("Error", "Por favor, selecciona una contraseña para eliminar.")

def round_image(image, corner_radius):
    mask = Image.new("L", image.size, 0)
    draw = ImageDraw.Draw(mask)
    draw.rounded_rectangle([0, 0, image.size[0], image.size[1]], corner_radius, fill=255)
    image.putalpha(mask)
    return image

# Crear la ventana principal
window = tk.Tk()
window.title("Gestor de Contraseñas")
window.geometry("850x750")  
window.resizable(False, False)
window.configure(bg='#2C2C2C')  # Fondo oscuro

# Frame centrado
frame = tk.Frame(window, bg='#3E3E3E', padx=20, pady=20)  
frame.place(relx=0.5, rely=0.5, anchor="center")

# Cargar imagen
image = Image.open(image_path)
image = image.resize((100, 100))
image = round_image(image, 20)
image = ImageTk.PhotoImage(image)

# Añadir la imagen al frame
image_label = tk.Label(frame, image=image, bg='#3E3E3E')
image_label.pack(pady=(10, 10))

# Títulos centrados
title_label = tk.Label(frame, text="ZomBits", font=("Arial", 24, "bold"), bg='#3E3E3E', fg='#FFD700')
title_label.pack(pady=(5, 5))

subtitle_label = tk.Label(frame, text="Gestiona tus contraseñas y despreocúpate de olvidarlas", font=("Arial", 12), bg='#3E3E3E', fg='white')
subtitle_label.pack(pady=(0, 20))

# Etiquetas y campos de texto
tk.Label(frame, text="Sitio Web:", bg='#3E3E3E', fg='white', font=("Arial", 12)).pack(anchor="w", padx=10)
site_entry = tk.Entry(frame, width=40, bg='#1C1C1C', fg='white', insertbackground='white', font=("Arial", 12))
site_entry.pack(pady=(0, 10))

tk.Label(frame, text="Contraseña:", bg='#3E3E3E', fg='white', font=("Arial", 12)).pack(anchor="w", padx=10)
password_entry = tk.Entry(frame, show="*", width=40, bg='#1C1C1C', fg='white', insertbackground='white', font=("Arial", 12))
password_entry.pack(pady=(0, 10))

# Listbox para mostrar contraseñas
password_list = tk.Listbox(frame, width=60, height=5, bg='#2C2C2C', fg='white', font=("Arial", 12))
password_list.pack(pady=(10, 10))

# Botones para guardar, verificar, editar y eliminar
button_frame = tk.Frame(frame, bg="#3E3E3E")  
button_frame.pack(pady=20)

save_button = tk.Button(button_frame, text="Guardar Contraseña", command=add_password, bg='#336600', fg='white', relief="flat", font=("Arial", 12))
save_button.pack(side="left", padx=5)

verify_button = tk.Button(button_frame, text="Verificar Contraseña", command=verify_password, bg='#330066', fg='white', relief="flat", font=("Arial", 12))
verify_button.pack(side="left", padx=5)

edit_button = tk.Button(button_frame, text="Editar Contraseña", command=edit_password, bg='#FF3300', fg='white', relief="flat", font=("Arial", 12))
edit_button.pack(side="left", padx=5)

delete_button = tk.Button(button_frame, text="Eliminar Contraseña", command=delete_password, bg='#CC0000', fg='white', relief="flat", font=("Arial", 12))
delete_button.pack(side="left", padx=5)

load_passwords()  # Cargar contraseñas al inicio

# Ejecutar el bucle principal
window.mainloop()
