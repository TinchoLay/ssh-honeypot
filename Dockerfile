# Imagen base — Python 3.11 sobre Alpine Linux
# Alpine es una distro muy liviana (~5MB) ideal para contenedores
FROM python:3.11-alpine

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

# Instalar dependencias del sistema necesarias para paramiko
# gcc y musl-dev son necesarios para compilar algunas librerías de Python en Alpine
RUN apk add --no-cache gcc musl-dev libffi-dev && \
    pip install --no-cache-dir -r requirements.txt && \
    apk del gcc musl-dev libffi-dev

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
ENV GEO_ENABLED=true
ENV EMAIL_ENABLED=false
ENV THREAT_INTEL_ENABLED=false

# Comando que se ejecuta cuando arranca el contenedor
CMD ["python", "honeypot.py"]