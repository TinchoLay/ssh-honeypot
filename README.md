# 🍯 SSH Honeypot

**[Español](#español) | [English](#english)**

---

## Español

Un honeypot es un servidor señuelo: parece real, acepta conexiones, pero no tiene nada de valor adentro. Su único trabajo es atraer atacantes y registrar todo lo que hacen. Este proyecto simula tres servicios distintos (SSH, HTTP y FTP) y quedó corriendo en una VM real de Azure, expuesta a internet, recibiendo tráfico de atacantes reales.

### ¿Qué hace?

Alguien intenta conectarse a uno de los puertos abiertos, pensando que encontró un servidor de verdad. El honeypot lo deja entrar, guarda el usuario y la contraseña que probó, y ubica geográficamente su IP. A partir de ahí:

- Un modelo de machine learning intenta adivinar qué tipo de atacante es (¿un bot que prueba miles de combinaciones, o alguien más metódico apuntando a este servidor en particular?)
- Analiza el "banner" que manda el cliente SSH al conectarse — una especie de firma que delata qué herramienta está usando (Hydra, Metasploit, un script casero, etc.)
- Si el atacante intenta descargar un archivo con `wget` o `curl`, el honeypot lo deja creer que funcionó, pero en paralelo descarga el archivo real para analizarlo
- Cruza la IP contra bases de datos de reputación (AbuseIPDB, Shodan) para ver si ya fue reportada antes
- Muestra todo en vivo en un dashboard web

### Los tres servicios falsos

- **SSH (puerto 2222):** el más elaborado. No solo acepta el login — abre una shell interactiva falsa. El atacante puede tipear `ls`, `whoami`, `cat /etc/passwd`, y recibe respuestas que imitan a un Ubuntu 22.04 real. Todo lo que escribe queda guardado.
- **HTTP (puerto 8080):** un panel de administración falso, con la pinta de un router TP-Link. Apunta a atrapar scanners que buscan paneles mal protegidos.
- **FTP (puerto 2121):** acepta la conexión, pero rechaza cualquier credencial. Sirve principalmente para ver qué usuarios y contraseñas prueban ahí también.

### Cómo clasifica a los atacantes

Usa un Random Forest (un tipo de modelo de machine learning) entrenado con los datos que va capturando, y lo reentrena automáticamente cada 100 intentos. Divide a los atacantes en cuatro grupos:

- `bot_fuerza_bruta` — scripts que prueban credenciales a toda velocidad, sin pausas
- `scanner` — está barriendo puertos y servicios, no busca entrar en particular
- `script_kiddie` — usa herramientas conocidas (tipo Hydra) pero sin mucho criterio
- `atacante_dirigido` — más lento, más humano, parece tener este servidor puntual como objetivo

### Análisis de malware

Cuando alguien intenta bajar un archivo, el honeypot lo descarga de verdad en segundo plano, calcula su hash (MD5 y SHA256— una especie de huella digital del archivo) y lo consulta contra VirusTotal, que lo analiza con decenas de antivirus distintos. El resultado queda guardado con el detalle de cuántos motores lo marcaron como malicioso.

### Dashboard en tiempo real

Un panel hecho con Flask y WebSockets que se actualiza solo apenas entra un ataque nuevo. Tiene tres pestañas:

- **Stats:** totales por protocolo, usuarios y contraseñas más probados, países de origen, log en vivo
- **Análisis:** gráficos de cuándo atacan (hora del día, día de la semana) y desde dónde
- **Mapa:** un mapa mundial con cada ataque marcado en su punto de origen

### Estructura del proyecto

```
ssh-honeypot/
├── honeypot.py          # Punto de entrada — arranca todos los servicios
├── fake_shell.py        # Shell SSH interactiva falsa
├── http_honeypot.py     # Servidor HTTP honeypot
├── ftp_honeypot.py      # Servidor FTP honeypot
├── logger.py            # Logging central + geolocalización
├── shell_logger.py      # Registro de comandos ejecutados
├── stats.py             # Estadísticas en consola
├── mapa.py              # Generador de mapa estático (folium)
├── dashboard.py         # Dashboard Flask + WebSockets
├── ml_classifier.py     # Clasificación ML de atacantes
├── fingerprint.py       # Identificación de herramientas
├── malware_capture.py   # Captura y análisis de malware
├── threat_intel.py      # Consultas a AbuseIPDB y Shodan
├── alertas.py           # Sistema de alertas por email
├── config.py            # Configuración central
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── logs/                # Generado al correr (no incluido en repo)
    ├── attempts.json
    ├── http_attempts.json
    ├── ftp_attempts.json
    ├── shell_commands.json
    ├── fingerprints.json
    ├── ml_classifications.json
    ├── malware_captures.json
    ├── threat_intel.json
    └── malware_samples/
```

### Stack técnico

| Categoría | Tecnología |
|---|---|
| Lenguaje | Python 3.11 |
| Protocolo SSH | paramiko |
| Web framework | Flask + Flask-SocketIO |
| Machine Learning | scikit-learn (Random Forest) |
| Mapas | folium, Leaflet.js |
| Geolocalización | ip-api.com |
| Threat Intel | AbuseIPDB API, Shodan API |
| Análisis de malware | VirusTotal API |
| Visualización | Chart.js |
| Infraestructura | Microsoft Azure (VM Ubuntu 22.04) |
| Contenedores | Docker + Docker Compose |

### Instalación local

**Requisitos:** Python 3.9+, pip

```bash
git clone https://github.com/TinchoLay/ssh-honeypot.git
cd ssh-honeypot

python -m venv venv

# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

pip install -r requirements.txt
python honeypot.py
```

El dashboard queda en `http://localhost:5000`.

### Despliegue en Azure

1. Crear una VM Ubuntu en Azure (el tier gratuito B1s alcanza para pruebas)
2. Abrir los puertos 2222, 8080, 2121 y 5000 en el Network Security Group
3. Conectarse por SSH, instalar Python y Git, clonar el repo
4. Crear el entorno virtual, instalar dependencias
5. Correr directo o con Docker

```bash
git clone https://github.com/TinchoLay/ssh-honeypot.git
cd ssh-honeypot
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 honeypot.py
```

Con Docker:

```bash
docker-compose up -d
```

### Variables de entorno opcionales

```bash
GEO_ENABLED=true              # Geolocalización de IPs (default: true)
EMAIL_ENABLED=false           # Alertas por email (default: false)
EMAIL_SENDER=tu@gmail.com
EMAIL_PASSWORD=app_password
EMAIL_RECEIVER=destino@gmail.com
ALERT_THRESHOLD=5             # Intentos antes de alertar (default: 5)
ALERT_WINDOW=60               # Ventana de tiempo en segundos (default: 60)
THREAT_INTEL_ENABLED=false    # Consultas a AbuseIPDB/Shodan (default: false)
ABUSEIPDB_KEY=tu_api_key
SHODAN_KEY=tu_api_key
VIRUSTOTAL_KEY=tu_api_key
```

### Qué se ve una vez expuesto a internet real

- Los primeros intentos llegan en minutos, sin necesidad de publicitar nada
- La mayoría del tráfico SSH es de bots que prueban siempre las mismas combinaciones: `root:123456`, `admin:admin`, `user:password`
- El tráfico HTTP viene sobre todo de scanners buscando paneles de administración (`/login`, `/admin`, `/wp-admin`)
- Las IPs más activas salen de nodos de salida de Tor, VPS de Linode/DigitalOcean, y bloques de IP chinos
- Los bots son sospechosamente constantes: intervalos de milisegundos entre intento e intento, sin ninguna variación

### Lo que aprendí armando esto

- Cómo funciona el protocolo SSH por dentro: negociación de claves, autenticación, canales
- Servidores TCP crudos con `socket` en Python
- Usar paramiko para interceptar y controlar sesiones SSH
- Flask con WebSockets para que el dashboard se actualice solo
- Entrenar e integrar un modelo de scikit-learn con datos reales
- Consumir APIs REST (ip-api, AbuseIPDB, Shodan, VirusTotal)
- Desplegar en la nube: VM, networking, reglas de firewall en Azure
- Concurrencia con `threading`
- Los dolores de cabeza reales de producción: correr en background, que los logs no se pierdan, reinicio automático si algo se cae

### Consideraciones éticas y legales

Este proyecto es para aprender ciberseguridad, nada más. El honeypot solo captura datos de gente que intenta entrar sin permiso a un servidor que es mío. No lo uses para atacar sistemas ajenos ni para nada malicioso.

### Autor

**Martín** — Estudiante de ciberseguridad orientado a roles de SOC Analyst.

[GitHub](https://github.com/TinchoLay) · [LinkedIn](https://linkedin.com/in/tu-perfil)

---

## English

A honeypot is a decoy server: it looks real, it accepts connections, but there's nothing of value inside. Its only job is to attract attackers and log everything they do. This project fakes three separate services (SSH, HTTP, and FTP) and ran on a real Azure VM, exposed to the internet, taking traffic from actual attackers.

### What it does, plainly

Someone connects to one of the open ports, thinking they've found a real server. The honeypot lets them in, records whatever username and password they tried, and looks up where their IP is coming from. From there:

- A machine learning model guesses what kind of attacker this is — a bot blasting through thousands of combinations, or someone slower and more deliberate, targeting this specific server?
- It reads the "banner" the SSH client sends on connect, a kind of fingerprint that gives away which tool is being used (Hydra, Metasploit, a homemade script, etc.)
- If the attacker tries to download something with `wget` or `curl`, the honeypot lets them think it worked, while quietly downloading the real file in the background to analyze it
- It checks the IP against reputation databases (AbuseIPDB, Shodan) to see if it's been reported before
- Everything shows up live on a web dashboard

### The three fake services

- **SSH (port 2222):** the most built-out one. It doesn't just accept the login — it opens a fake interactive shell. The attacker can type `ls`, `whoami`, `cat /etc/passwd`, and gets back responses that mimic a real Ubuntu 22.04 box. Everything they type gets logged.
- **HTTP (port 8080):** a fake admin panel styled after a TP-Link router. Meant to catch scanners hunting for poorly secured admin pages.
- **FTP (port 2121):** accepts the connection but rejects every credential. Mostly useful for seeing what usernames and passwords get tried there too.

### How attacker classification works

It uses a Random Forest (a type of machine learning model) trained on the data it captures, and retrains itself automatically every 100 attempts. Attackers get sorted into four buckets:

- `bot_fuerza_bruta` — automated scripts hammering through credentials at high speed
- `scanner` — sweeping for open ports and services, not trying to break into anything specific
- `script_kiddie` — using known tools (like Hydra) without much strategy behind it
- `atacante_dirigido` — slower, more human-looking behavior, seemingly targeting this server on purpose

### Malware analysis

When someone tries to pull a file, the honeypot actually downloads it in the background, computes its hash (MD5 and SHA256 — basically a fingerprint for the file) and checks it against VirusTotal, which scans it with dozens of different antivirus engines. The result gets saved along with how many engines flagged it as malicious.

### Real-time dashboard

A Flask + WebSockets panel that updates itself the moment a new attack comes in. Three tabs:

- **Stats:** totals per protocol, most-tried usernames and passwords, countries of origin, a live log
- **Analysis:** charts of when attacks happen (hour of day, day of week) and where from
- **Map:** a world map with every attack plotted at its point of origin

### Project structure

```
ssh-honeypot/
├── honeypot.py          # Entry point — starts all services
├── fake_shell.py        # Fake interactive SSH shell
├── http_honeypot.py     # HTTP honeypot server
├── ftp_honeypot.py      # FTP honeypot server
├── logger.py            # Central logging + geolocation
├── shell_logger.py      # Logs executed commands
├── stats.py             # Console stats
├── mapa.py              # Static map generator (folium)
├── dashboard.py         # Flask + WebSockets dashboard
├── ml_classifier.py     # ML attacker classification
├── fingerprint.py       # Tool identification
├── malware_capture.py   # Malware capture and analysis
├── threat_intel.py      # AbuseIPDB and Shodan lookups
├── alertas.py           # Email alert system
├── config.py            # Central config
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── logs/                # Generated at runtime (not in the repo)
    ├── attempts.json
    ├── http_attempts.json
    ├── ftp_attempts.json
    ├── shell_commands.json
    ├── fingerprints.json
    ├── ml_classifications.json
    ├── malware_captures.json
    ├── threat_intel.json
    └── malware_samples/
```

### Tech stack

| Category | Technology |
|---|---|
| Language | Python 3.11 |
| SSH protocol | paramiko |
| Web framework | Flask + Flask-SocketIO |
| Machine learning | scikit-learn (Random Forest) |
| Maps | folium, Leaflet.js |
| Geolocation | ip-api.com |
| Threat intel | AbuseIPDB API, Shodan API |
| Malware analysis | VirusTotal API |
| Visualization | Chart.js |
| Infrastructure | Microsoft Azure (Ubuntu 22.04 VM) |
| Containers | Docker + Docker Compose |

### Local setup

**Requirements:** Python 3.9+, pip

```bash
git clone https://github.com/TinchoLay/ssh-honeypot.git
cd ssh-honeypot

python -m venv venv

# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

pip install -r requirements.txt
python honeypot.py
```

The dashboard runs at `http://localhost:5000`.

### Deploying on Azure

1. Spin up an Ubuntu VM on Azure (the free B1s tier is enough for testing)
2. Open ports 2222, 8080, 2121, and 5000 in the Network Security Group
3. SSH into the VM, install Python and Git, clone the repo
4. Create a virtual environment, install dependencies
5. Run it directly or with Docker

```bash
git clone https://github.com/TinchoLay/ssh-honeypot.git
cd ssh-honeypot
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 honeypot.py
```

With Docker:

```bash
docker-compose up -d
```

### Optional environment variables

```bash
GEO_ENABLED=true              # IP geolocation (default: true)
EMAIL_ENABLED=false           # Email alerts (default: false)
EMAIL_SENDER=your@gmail.com
EMAIL_PASSWORD=app_password
EMAIL_RECEIVER=destination@gmail.com
ALERT_THRESHOLD=5             # Attempts before alerting (default: 5)
ALERT_WINDOW=60               # Time window in seconds (default: 60)
THREAT_INTEL_ENABLED=false    # AbuseIPDB/Shodan lookups (default: false)
ABUSEIPDB_KEY=your_api_key
SHODAN_KEY=your_api_key
VIRUSTOTAL_KEY=your_api_key
```

### What real internet traffic looks like

- The first connection attempts show up within minutes, no need to advertise the server anywhere
- Most SSH traffic comes from bots trying the same combinations over and over: `root:123456`, `admin:admin`, `user:password`
- HTTP traffic mostly comes from scanners hunting for admin panels (`/login`, `/admin`, `/wp-admin`)
- The most active IPs trace back to Tor exit nodes, Linode/DigitalOcean VPS ranges, and Chinese IP blocks
- The bots are suspiciously consistent — millisecond gaps between attempts, with basically no variation

### What I learned building this

- How SSH actually works under the hood: key negotiation, authentication, channels
- Raw TCP servers with Python's `socket` module
- Using paramiko to intercept and control SSH sessions
- Flask with WebSockets to keep the dashboard updating live
- Training and wiring up a scikit-learn model with real captured data
- Consuming REST APIs (ip-api, AbuseIPDB, Shodan, VirusTotal)
- Cloud deployment: VM setup, networking, firewall rules on Azure
- Concurrency with `threading`
- The unglamorous production stuff: running in the background, not losing logs, restarting automatically when something crashes

### Ethics and legal notes

This project exists purely to learn cybersecurity. The honeypot only captures data from people trying to break into a server that's mine, without permission. Don't use it to attack systems that aren't yours, and don't use it for anything malicious.

### Author

**Martín** — Cybersecurity student aiming for SOC Analyst roles.

[GitHub](https://github.com/TinchoLay) · [LinkedIn](https://linkedin.com/in/tu-perfil)
