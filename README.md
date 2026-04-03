# 🍯 SSH Honeypot

Un honeypot SSH hecho en Python que simula un servidor SSH real para capturar intentos de acceso no autorizados.

## ¿Qué hace?
- Simula un servidor SSH en el puerto 2222
- Registra cada intento de login (IP, usuario y contraseña)
- Guarda los datos en formato JSON para su análisis

## Instalación
```bash
git clone https://github.com/TuUsuario/ssh-honeypot.git
cd ssh-honeypot
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Uso
```bash
python honeypot.py
```

## ⚠️ Aviso legal
Este proyecto es únicamente con fines educativos.