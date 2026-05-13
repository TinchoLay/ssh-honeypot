# 🍯 SSH Honeypot

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![License](https://img.shields.io/badge/License-Educational-green)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker)
![GitHub](https://img.shields.io/badge/GitHub-TinchoLay-181717?logo=github)

Un honeypot multi-servicio hecho en Python que captura, analiza y clasifica intentos de acceso no autorizados en tiempo real. Proyecto de ciberseguridad orientado a threat intelligence y análisis de comportamiento de atacantes.

---

## 🎯 ¿Qué hace?

- **SSH Honeypot** con fake shell interactiva que simula un Ubuntu real
- **HTTP Honeypot** con panel de administración falso (router TP-Link)
- **FTP Honeypot** que captura credenciales FTP
- **Geolocalización** automática de IPs atacantes
- **Dashboard web** en tiempo real con WebSockets — incluye ataques SSH, HTTP y FTP unificados
- **Mapa de calor** mundial interactivo embebido en el dashboard (`/mapa`)
- **Threat Intelligence** cruzando IPs con AbuseIPDB y Shodan
- **Fingerprinting** de herramientas atacantes (Hydra, Metasploit, etc.)
- **Machine Learning** que clasifica atacantes automáticamente
- **Captura de malware** con análisis automático via VirusTotal
- **Alertas por email** ante ataques de fuerza bruta
- **Análisis temporal** con gráficos interactivos por tipo de servicio

---

## 🏗️ Arquitectura

```
ssh-honeypot/
├── honeypot.py          # Servidor SSH principal + arranca todos los servicios
├── fake_shell.py        # Shell interactiva falsa
├── shell_logger.py      # Logger de comandos de shell
├── http_honeypot.py     # Servidor HTTP falso
├── ftp_honeypot.py      # Servidor FTP falso
├── logger.py            # Sistema de logging con geolocalización
├── alertas.py           # Alertas por email
├── fingerprint.py       # Fingerprinting de herramientas
├── threat_intel.py      # Integración AbuseIPDB + Shodan
├── ml_classifier.py     # Clasificador ML con RandomForest
├── malware_capture.py   # Captura y análisis de malware
├── dashboard.py         # Dashboard web Flask + WebSockets (SSH+HTTP+FTP)
├── stats.py             # Estadísticas en consola
├── mapa.py              # Generador de mapa de calor (archivo externo)
├── config.py            # Configuración centralizada
├── templates/
│   ├── index.html       # Dashboard principal
│   ├── analisis.html    # Análisis temporal
│   └── mapa.html        # Mapa de calor embebido
└── logs/                # Datos capturados
```

---

## 🚀 Instalación

```bash
git clone https://github.com/TinchoLay/ssh-honeypot.git
cd ssh-honeypot
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate

pip install -r requirements.txt
```

---

## ⚙️ Configuración

Editá `config.py` con tus credenciales:

```python
# Email para alertas
EMAIL_SENDER   = "tu_email@gmail.com"
EMAIL_PASSWORD = "contraseña_de_aplicacion"
EMAIL_RECEIVER = "tu_email@gmail.com"

# APIs de Threat Intelligence
ABUSEIPDB_KEY  = "tu_api_key"
SHODAN_KEY     = "tu_api_key"
VIRUSTOTAL_KEY = "tu_api_key"
```

---

## ▶️ Uso

**Correr todo con un solo comando** (SSH + HTTP + FTP + Dashboard):
```bash
python honeypot.py
```

El dashboard arranca automáticamente en el puerto 5000. Ya no hace falta correrlo por separado.

**Ver estadísticas en consola:**
```bash
# Mientras corre el honeypot, escribí:
stats
```

**Generar mapa de calor como archivo HTML independiente:**
```bash
python mapa.py
```

---

## 🖥️ Dashboard

El dashboard web unifica eventos de los tres servicios en tiempo real.

| Ruta | Descripción |
|------|-------------|
| `/` | Panel principal con stats de SSH + HTTP + FTP |
| `/analisis` | Análisis temporal por hora, día y país |
| `/mapa` | Mapa de calor mundial interactivo (auto-refresh 30s) |
| `/api/stats` | JSON con estadísticas actuales |
| `/api/analisis` | JSON con datos de análisis temporal |

---

## 🐳 Docker

```bash
# Construir
docker build -t ssh-honeypot .

# Correr
docker run -p 2222:2222 -p 8080:8080 -p 2121:2121 -p 5000:5000 ssh-honeypot

# O con Docker Compose
docker-compose up
```

**Imagen pública:**
```bash
docker pull martinlay/ssh-honeypot
docker run -p 2222:2222 -p 5000:5000 martinlay/ssh-honeypot
```

---

## 🔌 Puertos

| Puerto | Servicio | Descripción |
|--------|----------|-------------|
| 2222 | SSH | Fake shell interactiva |
| 8080 | HTTP | Panel de admin falso |
| 2121 | FTP | Servidor FTP falso |
| 5000 | Dashboard | Panel web en tiempo real |

---

## 🤖 Machine Learning

El clasificador usa **RandomForest** con 7 features de comportamiento:

| Categoría | Descripción |
|-----------|-------------|
| `bot_fuerza_bruta` | Script automatizado probando miles de combinaciones |
| `scanner` | Verifica si el puerto está abierto |
| `script_kiddie` | Usa herramientas conocidas sin personalización |
| `atacante_dirigido` | Humano con objetivo específico |

El modelo se re-entrena automáticamente cada 100 ataques reales.

---

## 📊 Stack tecnológico

| Área | Tecnología |
|------|------------|
| Backend | Python 3.11, Flask, paramiko |
| ML | scikit-learn, RandomForest, numpy |
| Frontend | Chart.js, WebSockets, HTML/CSS |
| Mapas | Leaflet.js (embebido en dashboard) |
| Threat Intel | AbuseIPDB API, Shodan API, VirusTotal API |
| DevOps | Docker, Docker Compose |

---

## ☁️ Deploy en Azure

Para correr en una VM de Azure:

1. Crear VM (Standard B2ats v2 recomendado)
2. Abrir los siguientes puertos en el NSG (Network Security Group):

| Priority | Nombre | Puerto |
|----------|--------|--------|
| 100 | Allow-SSH-Honeypot | 2222 |
| 110 | Allow-HTTP-Honeypot | 8080 |
| 120 | Allow-FTP-Honeypot | 2121 |
| 130 | Allow-Dashboard | 5000 |

3. Instalar dependencias y correr con `screen` para que sobreviva desconexiones:

```bash
screen -S honeypot
source venv/bin/activate
python3 honeypot.py
# Ctrl+A, D para desconectarse sin matar el proceso
```

4. Para volver a conectarse a la sesión:
```bash
screen -r honeypot
```

> ⚠️ Apagá la VM cuando no la uses para no consumir créditos innecesariamente.

---

## ⚠️ Aviso legal

Este proyecto es únicamente con fines **educativos y de investigación en ciberseguridad**. No usar para actividades ilegales. El autor no se responsabiliza por el uso indebido de este software.

---

## 👤 Autor

**Martín Chancalay**
- GitHub: [@TinchoLay](https://github.com/TinchoLay)
- LinkedIn: [martin-c-902b543a8](https://linkedin.com/in/martin-c-902b543a8)
