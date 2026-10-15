# Imagen base: Python 3.11 sobre Debian (slim)
# Se usa Debian y no Alpine porque scikit-learn no publica wheels para Alpine (musl):
# en Alpine pip intenta compilarlo desde el codigo fuente y falla sin g++.
FROM python:3.11-slim

# Metadatos del contenedor
LABEL maintainer="TinchoLay"
LABEL description="SSH Honeypot - Captura intentos de acceso no autorizados"
LABEL version="1.0"

# Crear directorio de trabajo dentro del contenedor
WORKDIR /app

# Copiar primero solo el requirements.txt
# Esto permite que Docker cachee las dependencias y no las reinstale
# cada vez que cambia el código
COPY requirements.txt .

# Instalar dependencias de Python (todas tienen wheels precompilados para Debian)
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el resto del código
COPY *.py .
COPY templates/ templates/

# Crear la carpeta de logs dentro del contenedor
RUN mkdir -p logs

# Exponer los puertos que usa el honeypot
# EXPOSE es documentación — le dice a Docker qué puertos usa la app
EXPOSE 2222
EXPOSE 8080
EXPOSE 2121

# Variables de entorno con valores por defecto
# Se pueden sobreescribir al correr el contenedor
# Salida sin buffer: que los mensajes aparezcan al instante en docker compose logs
ENV PYTHONUNBUFFERED=1
ENV GEO_ENABLED=true
ENV EMAIL_ENABLED=false
ENV THREAT_INTEL_ENABLED=false

# Comando que se ejecuta cuando arranca el contenedor
CMD ["python", "honeypot.py"]