# 🍯 SSH Honeypot

Un honeypot multi-servicio hecho en Python que captura y analiza intentos de acceso no autorizados en tiempo real.

## ¿Qué hace?
- Simula servidores SSH, HTTP y FTP para atraer atacantes
- Registra IPs, credenciales, geolocalización y comandos ejecutados
- Fake shell interactiva que simula un Ubuntu real
- Dashboard web en tiempo real
- Mapa de calor mundial de ataques
- Alertas por email ante ataques de fuerza bruta
- Threat Intelligence con AbuseIPDB y Shodan
- Fingerprinting de herramientas atacantes

## 🐳 Correrlo con Docker (más fácil)

```bash
docker pull martinlay/ssh-honeypot
docker run -p 2222:2222 -p 8080:8080 -p 2121:2121 martinlay/ssh-honeypot
```

## Instalación manual

```bash
git clone https://github.com/TinchoLay/ssh-honeypot.git
cd ssh-honeypot
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python honeypot.py
```

## Servicios
| Puerto | Servicio | Descripción |
|--------|----------|-------------|
| 2222   | SSH      | Fake shell interactiva |
| 8080   | HTTP     | Panel de admin falso |
| 2121   | FTP      | Servidor FTP falso |

## Dashboard
Corré el dashboard en una terminal separada:
```bash
python dashboard.py
```
Abrí `http://localhost:5000` en el navegador.

## ⚠️ Aviso legal
Este proyecto es únicamente con fines educativos.