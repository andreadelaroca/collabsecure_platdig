import os
import hashlib
import datetime
import time
import sqlite3  # Librería para la base de datos

# --- 1. CONFIGURACIÓN DE BASE DE DATOS ---

DB_NAME = "collabsecure.db"

def init_db():
    """Inicializa la base de datos y crea las tablas si no existen."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Tabla de Usuarios
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL
        )
    ''')
    
    # Tabla de Mensajes
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            author TEXT,
            encrypted_content TEXT
        )
    ''')
    
    # Crear usuario Admin por defecto si no existe
    # Pass: 1234
    admin_pass = hashlib.sha256("1234".encode()).hexdigest()
    try:
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", ("admin", admin_pass))
        conn.commit()
    except sqlite3.IntegrityError:
        pass # El admin ya existe
        
    conn.close()

# --- 2. FUNCIONES DE SEGURIDAD Y ÉTICA ---

def limpiar_pantalla():
    os.system('cls' if os.name == 'nt' else 'clear')

def hash_password(password):
    """SHA-256 para proteger contraseñas."""
    return hashlib.sha256(password.encode()).hexdigest()

def encriptar_mensaje(texto):
    """Simula encriptación a Hexadecimal."""
    return texto.encode('utf-8').hex()

def desencriptar_mensaje(texto_hex):
    """Revierte la encriptación."""
    try:
        return bytes.fromhex(texto_hex).decode('utf-8')
    except:
        return "[Error de datos]"

def es_etico(texto):
    """Filtro de contenido ofensivo."""
    palabras_prohibidas = ["idiota", "estupido", "muere", "tonto", "inutil", "hackear"]
    texto_lower = texto.lower()
    for palabra in palabras_prohibidas:
        if palabra in texto_lower:
            return False
    return True

# --- 3. LÓGICA DE USUARIOS Y MENSAJES ---

def registrar_usuario():
    limpiar_pantalla()
    print("--- REGISTRO DE NUEVO USUARIO ---")
    nuevo_user = input("Ingrese nombre de usuario: ").strip()
    
    if not nuevo_user:
        print("El usuario no puede estar vacío.")
        time.sleep(1)
        return

    nuevo_pass = input("Ingrese contraseña: ").strip()
    if len(nuevo_pass) < 4:
        print("¡Inseguro! La contraseña debe tener al menos 4 caracteres.") # Medida de seguridad básica
        time.sleep(2)
        return

    # Guardar en DB
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    try:
        hash_pw = hash_password(nuevo_pass)
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (nuevo_user, hash_pw))
        conn.commit()
        print(f"\n[ÉXITO] Usuario '{nuevo_user}' registrado correctamente.")
        print("Aviso de Privacidad: Sus datos han sido cifrados.")
    except sqlite3.IntegrityError:
        print("\n[ERROR] El nombre de usuario ya existe.")
    finally:
        conn.close()
        time.sleep(2)

def validar_login(usuario, password):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (usuario,))
    resultado = cursor.fetchone()
    conn.close()
    
    if resultado:
        db_hash = resultado[0]
        input_hash = hash_password(password)
        return db_hash == input_hash
    return False

def guardar_mensaje(autor, contenido):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    fecha = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    contenido_seguro = encriptar_mensaje(contenido)
    
    cursor.execute("INSERT INTO messages (timestamp, author, encrypted_content) VALUES (?, ?, ?)", 
                   (fecha, autor, contenido_seguro))
    conn.commit()
    conn.close()

def obtener_mensajes():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, author, encrypted_content FROM messages")
    mensajes = cursor.fetchall()
    conn.close()
    return mensajes

# --- 4. INTERFAZ DE USUARIO ---

def menu_inicio():
    while True:
        limpiar_pantalla()
        print("="*40)
        print("   COLLABSECURE - BASE DE DATOS SEGURA")
        print("="*40)
        print("1. Iniciar Sesión")
        print("2. Registrar Nuevo Usuario")
        print("3. Salir")
        
        opcion = input("\nOpción: ")
        
        if opcion == "1":
            login_screen()
        elif opcion == "2":
            registrar_usuario()
        elif opcion == "3":
            print("Cerrando sistema...")
            break
        else:
            print("Opción inválida.")

def login_screen():
    limpiar_pantalla()
    print("--- INICIO DE SESIÓN ---")
    user = input("Usuario: ")
    pw = input("Contraseña: ")
    
    if validar_login(user, pw):
        print("\nAutenticación Exitosa.")
        time.sleep(1)
        menu_principal(user)
    else:
        print("\n[ERROR] Credenciales incorrectas.")
        time.sleep(2)

def menu_principal(usuario_actual):
    while True:
        limpiar_pantalla()
        print(f"Usuario: {usuario_actual} | Estado: Conectado")
        print("-" * 40)
        print("1. Leer Mensajes (Desencriptar DB)")
        print("2. Escribir Mensaje")
        print("3. Cerrar Sesión")
        
        opcion = input("\nOpción: ")
        
        if opcion == "1":
            ver_mensajes()
        elif opcion == "2":
            escribir_nuevo(usuario_actual)
        elif opcion == "3":
            break

def ver_mensajes():
    limpiar_pantalla()
    mensajes = obtener_mensajes()
    print(f"{'FECHA':<18} | {'AUTOR':<10} | {'MENSAJE'}")
    print("-" * 60)
    
    if not mensajes:
        print("La base de datos está vacía.")
    
    for fecha, autor, contenido_hex in mensajes:
        msg_claro = desencriptar_mensaje(contenido_hex)
        print(f"{fecha:<18} | {autor:<10} | {msg_claro}")
        
    input("\nPresione ENTER para volver...")

def escribir_nuevo(autor):
    print("\n--- NUEVO MENSAJE ---")
    msg = input("Mensaje: ")
    
    if not es_etico(msg):
        print("\n[BLOQUEADO] El sistema detectó lenguaje inapropiado.")
        time.sleep(2)
        return
        
    guardar_mensaje(autor, msg)
    print("Mensaje guardado y cifrado en la base de datos.")
    time.sleep(1)

# --- EJECUCIÓN ---
if __name__ == "__main__":
    init_db() # Crear DB y tablas al arrancar
