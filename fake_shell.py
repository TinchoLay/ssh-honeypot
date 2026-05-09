import paramiko
import threading
from datetime import datetime
from shell_logger import save_command

# Respuestas falsas para los comandos más comunes
# El atacante ve output realista pero nada es real
COMANDOS = {
    "ls": "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var",
    "ls -la": """total 68
drwxr-xr-x  18 root root 4096 Apr 27 03:14 .
drwxr-xr-x  18 root root 4096 Apr 27 03:14 ..
drwxr-xr-x   2 root root 4096 Apr 27 03:14 bin
drwxr-xr-x   3 root root 4096 Apr 27 03:14 boot
drwxr-xr-x   2 root root 4096 Apr 27 03:14 etc
drwxr-xr-x   3 root root 4096 Apr 27 03:14 home
drwxr-xr-x   2 root root 4096 Apr 27 03:14 tmp
drwxr-xr-x  10 root root 4096 Apr 27 03:14 var""",
    "whoami": "root",
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "uname -a": "Linux ubuntu-server 5.15.0-1034-aws #38-Ubuntu SMP Mon Mar 20 15:41:27 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux",
    "uname": "Linux",
    "pwd": "/root",
    "hostname": "ubuntu-server",
    "cat /etc/passwd": """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin""",
    "cat /etc/shadow": "Permission denied",
    "cat /etc/os-release": """NAME="Ubuntu"
VERSION="22.04.2 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 22.04.2 LTS"
VERSION_ID="22.04"
HOME_URL="https://www.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=jammy""",
    "ifconfig": """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.1.47  netmask 255.255.255.0  broadcast 10.0.1.255
        inet6 fe80::4ab1:c1ff:fe8d:3a2e  prefixlen 64  scopeid 0x20<link>
        ether 48:b1:c1:8d:3a:2e  txqueuelen 1000  (Ethernet)
        RX packets 12483  bytes 18234521 (18.2 MB)
        TX packets 8291  bytes 1923847 (1.9 MB)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>""",
    "ip a": """1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP
    link/ether 48:b1:c1:8d:3a:2e brd ff:ff:ff:ff:ff:ff
    inet 10.0.1.47/24 brd 10.0.1.255 scope global eth0""",
    "ps aux": """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 169824 13412 ?        Ss   Apr26   0:04 /sbin/init
root       423  0.0  0.0  72300  5764 ?        Ss   Apr26   0:00 /usr/sbin/sshd
root       891  0.0  0.0  14224  2108 ?        S    Apr26   0:00 bash
www-data   234  0.0  0.1 200432 18234 ?        S    Apr26   0:12 apache2""",
    "netstat -an": """Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN""",
    "df -h": """Filesystem      Size  Used Avail Use% Mounted on
udev            7.8G     0  7.8G   0% /dev
tmpfs           1.6G  1.2M  1.6G   1% /run
/dev/xvda1       99G   18G   81G  19% /
tmpfs           7.9G     0  7.9G   0% /dev/shm""",
    "free -h": """              total        used        free      shared  buff/cache   available
Mem:           15Gi       2.1Gi        11Gi       134Mi       2.0Gi        12Gi
Swap:         2.0Gi          0B       2.0Gi""",
    "env": """PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOME=/root
SHELL=/bin/bash
USER=root
LOGNAME=root
TERM=xterm-256color""",
    "history": """    1  ls
    2  cd /tmp
    3  ps aux
    4  whoami
    5  uname -a""",
    "crontab -l": "no crontab for root",
    "exit": "exit",
    "logout": "exit",
}

def get_response(comando, ip):
    """Devuelve la respuesta para un comando dado."""
    cmd = comando.strip()
    
    # Comandos de salida
    if cmd in ["exit", "logout", "quit"]:
        return None  # None = cerrar la sesión
    
    # Comando vacío
    if not cmd:
        return ""
    
    # Detectar comandos de descarga
    if any(x in cmd for x in ["wget", "curl", "fetch"]):
        partes = cmd.split()
        url = next((p for p in partes if p.startswith("http")), None)
        
        if url:
            save_command(ip, cmd, f"ALERTA: Intento de descarga de {url}")
            # Capturar el malware en background
            from malware_capture import capturar_en_background
            capturar_en_background(url, ip)
            
            nombre = url.rstrip("/").split("/")[-1] or "payload"
            return (
                f"--2026-05-08 03:14:22-- {url}\n"
                f"Resolving {url.split('/')[2]}... connected.\n"
                f"HTTP request sent, awaiting response... 200 OK\n"
                f"Length: 4312 (4.2K) [text/plain]\n"
                f"Saving to: '{nombre}'\n\n"
                f"{nombre} 100%[==================>]   4.21K  --.-KB/s    in 0s\n\n"
                f"2026-05-08 03:14:22 (--.- MB/s) - '{nombre}' saved [4312/4312]"
            )
        else:
            save_command(ip, cmd, "ALERTA: Intento de descarga sin URL")
            return "wget: missing URL"
    
    # Detectar comandos de modificación del sistema
    if any(x in cmd for x in ["chmod", "chown", "useradd", "userdel", "passwd", "crontab -e"]):
        save_command(ip, cmd, "ALERTA: Intento de modificación del sistema")
        return ""
    
    # Buscar en el diccionario de respuestas
    if cmd in COMANDOS:
        return COMANDOS[cmd]
    
    # Comando no reconocido — simular error de bash
    cmd_base = cmd.split()[0] if cmd.split() else cmd
    return f"bash: {cmd_base}: command not found"


class FakeShell(paramiko.ServerInterface):
    """Servidor SSH que acepta el login y abre una shell falsa."""
    
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()
    
    def check_auth_password(self, username, password):
        # Guardar el intento de login
        from logger import save_attempt
        save_attempt(self.client_ip, username, password)
        
        # Aceptar el login después de algunos intentos fallidos
        # para que parezca más realista
        self.username = username
        return paramiko.AUTH_SUCCESSFUL
    
    def get_allowed_auths(self, username):
        return "password"
    
    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


def manejar_shell(channel, client_ip, username):
    """Maneja la sesión interactiva de la shell falsa."""
    prompt = f"root@ubuntu-server:~$ "
    
    # Mensaje de bienvenida — igual al de Ubuntu real
    bienvenida = f"""Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-1034-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Last login: {datetime.now().strftime("%a %b %d %H:%M:%S %Y")} from {client_ip}
"""
    channel.send(bienvenida.encode())
    channel.send(prompt.encode())
    
    comando_actual = ""
    
    while True:
        try:
            # Leer caracter por caracter
            data = channel.recv(1024)
            if not data:
                break
            
            for byte in data:
                char = chr(byte)
                
                # Enter — ejecutar el comando
                if char == "\r" or char == "\n":
                    channel.send(b"\r\n")
                    
                    if comando_actual.strip():
                        # Guardar el comando en el log
                        save_command(client_ip, comando_actual.strip())
                        
                        # Obtener la respuesta
                        respuesta = get_response(comando_actual.strip(), client_ip)
                        
                        # None significa que pidió exit
                        if respuesta is None:
                            channel.send(b"logout\r\n")
                            channel.close()
                            return
                        
                        if respuesta:
                            channel.send((respuesta + "\r\n").encode())
                    
                    comando_actual = ""
                    channel.send(prompt.encode())
                
                # Backspace
                elif byte == 127 or byte == 8:
                    if comando_actual:
                        comando_actual = comando_actual[:-1]
                        channel.send(b"\b \b")
                
                # Caracteres normales
                elif 32 <= byte <= 126:
                    comando_actual += char
                    channel.send(char.encode())
        
        except Exception:
            break
    
    channel.close()