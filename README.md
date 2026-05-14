# 🍯 SSH Honeypot

Honeypot multi-servicio construido desde cero en Python. Simula servidores SSH, HTTP y FTP para capturar intentos de acceso no autorizados, analizar el comportamiento de los atacantes y visualizar los datos en tiempo real.

Desplegado en una máquina virtual Ubuntu en Microsoft Azure con tráfico real de internet.

---

## ¿Qué hace?

Cuando alguien intenta conectarse a los puertos expuestos, el honeypot:

- Acepta la conexión y simula un servidor real
- Captura las credenciales probadas (usuario y contraseña)
- Geolocaliza la IP del atacante
- Clasifica el tipo de atacante usando machine learning
- Identifica la herramienta usada (Hydra, Metasploit, scripts custom, etc.)
- Captura y analiza archivos de malware si el atacante intenta descargarlos
- Consulta bases de datos de threat intelligence (AbuseIPDB, Shodan)
- Muestra todo en un dashboard web en tiempo real

---

## Características

### Protocolos soportados
- **SSH** (puerto 2222) — shell interactiva falsa con respuestas realistas
- **HTTP** (puerto 8080) — panel de admin falso estilo router TP-Link
- **FTP** (puerto 2121) — servidor FTP que acepta conexiones y rechaza credenciales

### Shell interactiva
El honeypot SSH acepta el login y abre una shell falsa. El atacante puede ejecutar comandos (`ls`, `whoami`, `cat /etc/passwd`, `ps aux`, etc.) y recibe respuestas realistas de un Ubuntu 22.04. Los comandos quedan registrados en el log.

Si el atacante intenta descargar algo con `wget` o `curl`, el honeypot simula la descarga exitosa y en paralelo descarga el archivo real para analizarlo.

### Machine Learning
Clasifica a cada atacante en una de cuatro categorías usando un Random Forest:
- `bot_fuerza_bruta` — scripts automatizados de alta velocidad
- `scanner` — buscando puertos y servicios abiertos
- `script_kiddie` — usando herramientas conocidas sin mucho criterio
- `atacante_dirigido` — comportamiento más lento y humano, con objetivo específico

El modelo se re-entrena automáticamente cada 100 intentos incorporando los datos reales capturados.

### Fingerprinting
Identifica la herramienta del atacante analizando el banner SSH del cliente. Detecta Hydra, Metasploit, Paramiko, AsyncSSH, Nmap, Masscan, PuTTY, WinSCP y más. También analiza la velocidad y regularidad de los intentos para distinguir bots de humanos.

### Captura de malware
Cuando el atacante ejecuta `wget` o `curl` con una URL, el honeypot descarga el archivo en background, calcula sus hashes MD5 y SHA256, y lo consulta en VirusTotal. El reporte queda guardado con el nivel de detección de cada antivirus.

### Threat Intelligence
Consulta AbuseIPDB y Shodan para cada IP atacante. Muestra el historial de reportes, el score de confianza de malicio, puertos abiertos conocidos y vulnerabilidades asociadas.

### Alertas por email
Opcional. Si una IP supera el umbral de intentos configurado dentro de la ventana de tiempo, manda un email de alerta automático vía Gmail SMTP.

### Dashboard web en tiempo real
Panel Flask con WebSockets (Socket.IO) que se actualiza automáticamente con cada nuevo ataque. Incluye tres secciones:

- **Stats** — totales de ataques por protocolo, top usuarios, top contraseñas, top países, log en vivo
- **Análisis** — gráficos de ataques por hora del día, por día de la semana, por país y evolución temporal
- **Mapa** — mapa mundial interactivo con los puntos de origen de los ataques (Leaflet + CartoDB)

---

## Estructura del proyecto

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

---

## Stack técnico

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

---

## Instalación local

**Requisitos:** Python 3.9+, pip

```bash
# Clonar el repositorio
git clone https://github.com/tu-usuario/ssh-honeypot.git
cd ssh-honeypot

# Crear entorno virtual
python -m venv venv

# Activar el entorno virtual
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt

# Correr el honeypot
python honeypot.py
```

El dashboard queda disponible en `http://localhost:5000`.

---

## Despliegue en Azure

El proyecto está corriendo en una VM Ubuntu 22.04 en Microsoft Azure.

### Pasos seguidos para el despliegue

1. Crear una VM Ubuntu en Azure (se puede usar el tier gratuito B1s para pruebas)
2. Configurar el Network Security Group para abrir los puertos 2222, 8080, 2121 y 5000
3. Conectarse por SSH a la VM
4. Instalar Python y Git, clonar el repositorio
5. Crear el entorno virtual e instalar dependencias
6. Correr el honeypot directamente o con Docker

```bash
# En la VM de Azure
git clone https://github.com/tu-usuario/ssh-honeypot.git
cd ssh-honeypot
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 honeypot.py
```

### Con Docker

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

---

## Datos capturados

### SSH (attempts.json)
```json
{
  "timestamp": "2026-05-14 14:37:23",
  "ip": "185.220.101.45",
  "country": "Germany",
  "city": "Frankfurt",
  "isp": "Tor Project",
  "lat": 50.1109,
  "lon": 8.6821,
  "username": "root",
  "password": "123456"
}
```

### Clasificación ML (ml_classifications.json)
```json
{
  "timestamp": "2026-05-14 14:37:23",
  "ip": "185.220.101.45",
  "categoria": "bot_fuerza_bruta",
  "confianza": 94.0,
  "features": {
    "velocidad_intentos_min": 45,
    "usuarios_distintos": 3,
    "passwords_distintas": 40,
    "uso_diccionario": true,
    "interactuó_shell": false,
    "comandos_ejecutados": 0,
    "variacion_temporal": 0.2
  }
}
```

### Captura de malware (malware_captures.json)
```json
{
  "timestamp": "2026-05-14 14:38:01",
  "ip": "185.220.101.45",
  "url": "http://malware.ru/payload.sh",
  "nombre_archivo": "payload.sh",
  "tamaño_bytes": 4312,
  "hashes": {
    "md5": "d8e8fca2dc0f896fd7cb4cb0031ba249",
    "sha256": "f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2"
  },
  "virustotal": {
    "maliciosos": 38,
    "total_motores": 72,
    "porcentaje": 52.8,
    "tipo_malware": "Trojan.GenericKD"
  }
}
```

---

## Observaciones del despliegue real

Una vez expuesto el servidor en internet, estos son los patrones observados con tráfico real:

- Los primeros intentos de conexión llegan en minutos, sin necesidad de publicar nada
- La mayoría del tráfico SSH viene de bots automatizados que prueban las mismas credenciales en orden: `root:123456`, `admin:admin`, `user:password`
- El tráfico HTTP proviene principalmente de scanners buscando paneles de administración (`/login`, `/admin`, `/wp-admin`)
- Las IPs más activas corresponden a rangos de salida de Tor, VPS de Linode/DigitalOcean y rangos chinos
- La velocidad de los bots es notablemente constante — intervalos de milisegundos entre intentos sin variación

---

## Lo que aprendí construyendo esto

- Cómo funciona el protocolo SSH por dentro (negociación de claves, autenticación, canales)
- Implementación de servidores TCP raw con `socket` en Python
- Uso de paramiko para interceptar y controlar sesiones SSH
- Flask con WebSockets para actualizaciones en tiempo real
- Entrenamiento e integración de modelos de clasificación con scikit-learn
- Consumo de APIs REST (ip-api, AbuseIPDB, Shodan, VirusTotal)
- Despliegue en la nube: configuración de VM, networking, NSG en Azure
- Manejo de concurrencia con `threading` en Python
- Problemas reales de producción: ejecución en background, logs persistentes, reinicio automático

---

## Consideraciones éticas y legales

Este proyecto es estrictamente para fines educativos y de investigación en ciberseguridad. El honeypot captura datos de atacantes que intentan acceder sin autorización a un servidor propio. No debe usarse para atacar sistemas de terceros ni para ningún uso malicioso.

---

## Autor

**Martín** — Estudiante de ciberseguridad y programación, orientado a roles de SOC Analyst.

[GitHub](https://github.com/tu-usuario) · [LinkedIn](https://linkedin.com/in/tu-perfil)
