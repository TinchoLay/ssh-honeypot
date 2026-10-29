import re
import shlex
import hashlib
import posixpath
import paramiko
import threading
from weak_passwords import CLAVES_DEBILES
from datetime import datetime, timedelta
from shell_logger import save_command
import shell_interp

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

# --- Sistema de archivos falso -------------------------------------------------
# La shell recuerda en que carpeta esta el atacante, asi cd, pwd, ls y el prompt
# son coherentes entre si. Un "ls" en el home que lista la raiz delataba al honeypot.
DIRS_CONOCIDOS = {"/", "/bin", "/boot", "/dev", "/dev/shm", "/etc", "/home", "/lib",
                  "/media", "/mnt", "/opt", "/proc", "/root", "/run", "/sbin", "/srv",
                  "/sys", "/tmp", "/usr", "/usr/bin", "/usr/local", "/usr/share",
                  "/var", "/var/log", "/var/run", "/var/tmp", "/var/www"}

LISTADOS = {
    "/": "bin boot dev etc home lib media mnt opt proc root run sbin srv sys tmp usr var".split(),
    "/etc": ("apt bash.bashrc cron.d crontab fstab group hostname hosts issue motd "
             "os-release passwd profile resolv.conf shadow ssh sudoers").split(),
    "/var": "backups cache lib local lock log mail opt run spool tmp".split(),
    "/var/log": ("alternatives.log apt auth.log btmp cloud-init.log dpkg.log "
                 "kern.log lastlog syslog wtmp").split(),
    "/usr": "bin games include lib local sbin share src".split(),
}

TAMANOS_DOTFILES = {".bash_logout": 220, ".bashrc": 3771, ".profile": 807}

def _home(usuario):
    return "/root" if usuario == "root" else f"/home/{usuario}"

def _resolver(cwd, destino, usuario):
    home = _home(usuario)
    if not destino or destino == "~":
        ruta = home
    elif destino.startswith("~/"):
        ruta = home + destino[1:]
    elif destino.startswith("/"):
        ruta = destino
    else:
        ruta = posixpath.join(cwd, destino)
    return posixpath.normpath(ruta)

def _dir_existe(ruta, usuario):
    return ruta in DIRS_CONOCIDOS or ruta == _home(usuario)

def _nombres_dir(ruta, usuario):
    if ruta == "/home":
        nombres = ["ubuntu"]
        if usuario not in ("root", "ubuntu"):
            nombres.append(usuario)
        return sorted(nombres)
    return list(LISTADOS.get(ruta, []))

def _ls(argumentos, cwd, usuario):
    flags = "".join(a[1:] for a in argumentos if a.startswith("-"))
    destinos = [a for a in argumentos if not a.startswith("-")]
    ruta = _resolver(cwd, destinos[0], usuario) if destinos else cwd
    if not _dir_existe(ruta, usuario):
        return f"ls: cannot access '{destinos[0] if destinos else ruta}': No such file or directory"
    if ruta == "/root" and usuario != "root":
        return "ls: cannot open directory '/root': Permission denied"

    es_home = ruta == _home(usuario)
    nombres = _nombres_dir(ruta, usuario)
    if es_home:
        ocultos = [".bashrc", ".profile"] if usuario == "root" else \
                  [".bash_logout", ".bashrc", ".cache", ".profile"]
    else:
        ocultos = []

    if "l" not in flags:
        visibles = (ocultos if "a" in flags else []) + nombres
        return "  ".join(sorted(visibles, key=lambda n: n.lower().lstrip(".")))

    dueno = usuario if es_home else "root"
    entradas = []
    if "a" in flags:
        entradas += [".", ".."] + ocultos
    entradas += nombres
    lineas = [f"total {4 * max(len(entradas), 1)}"]
    for n in sorted(entradas, key=lambda x: (x not in (".", ".."), x.lower().lstrip("."))):
        if n in (".", ".."):
            es_dir, perm = True, ("drwxr-x---" if es_home and n == "." else "drwxr-xr-x")
            propietario = dueno if n == "." else "root"
        elif n == ".cache":
            es_dir, perm, propietario = True, "drwx------", dueno
        elif n in TAMANOS_DOTFILES:
            es_dir, perm, propietario = False, "-rw-r--r--", dueno
        else:
            es_dir = "." not in n
            perm = "drwxr-xr-x" if es_dir else "-rw-r--r--"
            propietario = dueno
        tam = 4096 if es_dir else TAMANOS_DOTFILES.get(n, 300 + (len(n) * 137) % 4000)
        enlaces = 2 if es_dir else 1
        lineas.append(f"{perm} {enlaces:>2} {propietario} {propietario} {tam:>5} Apr 27 03:14 {n}")
    return "\n".join(lineas)

def _prompt(usuario, estado):
    home = _home(usuario)
    cwd = estado["cwd"]
    if cwd == home:
        d = "~"
    elif cwd.startswith(home + "/"):
        d = "~" + cwd[len(home):]
    else:
        d = cwd
    simbolo = "#" if usuario == "root" else "$"
    return f"{usuario}@ubuntu-server:{d}{simbolo} "


def _ejecutar(comando, ip, usuario, estado):
    """Respuesta para UN comando suelto (sin ; && || sin comillas). Ver get_response."""
    cmd = comando.strip()

    # Comandos de salida
    if cmd in ["exit", "logout", "quit"]:
        return None  # None = cerrar la sesión
    
    # Comando vacío
    if not cmd:
        return ""

    # sh -c "..." y bash -c "...": se ejecuta lo que hay adentro. Va antes de la deteccion
    # de descargas para que un wget dentro de un sh -c se vea igual que uno suelto.
    if cmd.split()[0] in ("sh", "bash", "dash"):
        return _subshell(cmd, ip, usuario, estado)
    
    # Detectar comandos de descarga
    if any(x in cmd for x in ["wget", "curl", "fetch"]):
        m = _URL.search(cmd)
        url = m.group(0) if m else None
        
        if url:
            save_command(ip, cmd, f"ALERTA: Intento de descarga de {url}", canal=estado.get("canal", "shell"))
            # Capturar el malware en background
            from malware_capture import capturar_en_background
            capturar_en_background(url, ip)
            
            nombre = url.rstrip("/").split("/")[-1] or "payload"
            ahora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            return (
                f"--{ahora}-- {url}\n"
                f"Resolving {url.split('/')[2]}... connected.\n"
                f"HTTP request sent, awaiting response... 200 OK\n"
                f"Length: 4312 (4.2K) [text/plain]\n"
                f"Saving to: '{nombre}'\n\n"
                f"{nombre} 100%[==================>]   4.21K  --.-KB/s    in 0s\n\n"
                f"{ahora} (--.- MB/s) - '{nombre}' saved [4312/4312]"
            )
        else:
            save_command(ip, cmd, "ALERTA: Intento de descarga sin URL", canal=estado.get("canal", "shell"))
            return "wget: missing URL"
    
    # Detectar comandos de modificación del sistema
    if _MODIFICA.search(cmd):
        save_command(ip, cmd, "ALERTA: Intento de modificación del sistema", canal=estado.get("canal", "shell"))
        return ""
    
    # Respuestas que dependen del usuario con el que entro el atacante
    if cmd == "whoami":
        return usuario
    if cmd == "id":
        if usuario == "root":
            return "uid=0(root) gid=0(root) groups=0(root)"
        return f"uid=1000({usuario}) gid=1000({usuario}) groups=1000({usuario})"
    if cmd == "pwd":
        return estado["cwd"]

    # Comandos internos de bash que no imprimen nada. Si faltaran, "cd /tmp" daria
    # "command not found", que es lo primero que delata un honeypot.
    primera = cmd.split()[0]
    simple = not any(m in cmd for m in (";", "&&", "||", "|", ">", "<", "`", "$("))
    if primera == "cd" and simple:
        args = cmd.split()[1:]
        destino = args[0] if args else ""
        ruta = _resolver(estado["cwd"], destino, usuario)
        if ruta == "/root" and usuario != "root":
            return "bash: cd: /root: Permission denied"
        if _dir_existe(ruta, usuario):
            estado["cwd"] = ruta
            return ""
        return f"bash: cd: {destino}: No such file or directory"
    if primera == "ls" and simple:
        return _ls(cmd.split()[1:], estado["cwd"], usuario)
    if primera in ("cd", "touch", "mkdir", "rm", "sleep", "export", "unset", "set",
                   "source", "alias", "clear", "kill", "pkill", "nohup", "history -c",
                   "chattr"):
        return ""
    if primera == "echo":
        # Con redireccion o pipe el texto no sale por pantalla (echo "ssh-rsa ..." >> authorized_keys)
        if ">" in cmd or "|" in cmd:
            return ""
        return cmd[4:].strip().strip("\"'")

    if primera == "uname" and simple:
        return _uname(cmd.split()[1:])

    # Buscar en el diccionario de respuestas
    if cmd in COMANDOS:
        return COMANDOS[cmd]
    
    # Comando no reconocido — simular error de bash
    cmd_base = cmd.split()[0] if cmd.split() else cmd
    # Un binario con ruta ("./x.sh", "/tmp/x") que no existe da otro mensaje en bash
    if cmd_base.startswith(("./", "/")):
        return f"bash: {cmd_base}: No such file or directory"
    return f"bash: {cmd_base}: command not found"


_URL = re.compile(r"https?://[^\s'\"<>;|&`]+")
# chmod/chown/useradd... como palabra entera, y passwd solo como comando (no "/etc/passwd")
_MODIFICA = re.compile(
    r"\b(chmod|chown|useradd|userdel|usermod|adduser|chpasswd)\b|(?:^|[\s;&|])passwd(?:\s|$)|crontab\s+-e")

MAX_PARTES = 20        # comandos encadenados que se ejecutan
MAX_PROFUNDIDAD = 3    # sh -c dentro de sh -c

# uname: los valores salen de la linea de "uname -a" de COMANDOS
_UNAME = {"s": "Linux", "n": "ubuntu-server", "r": "5.15.0-1034-aws",
          "v": "#38-Ubuntu SMP Mon Mar 20 15:41:27 UTC 2023",
          "m": "x86_64", "p": "x86_64", "i": "x86_64", "o": "GNU/Linux"}
_UNAME_LARGAS = {"kernel-name": "s", "nodename": "n", "kernel-release": "r",
                 "kernel-version": "v", "machine": "m", "processor": "p",
                 "hardware-platform": "i", "operating-system": "o", "all": "a"}

def _uname(args):
    """uname con las opciones reales. El orden de la salida es siempre el mismo
    (nombre, host, release, version, maquina...), sin importar el orden de las opciones."""
    pedidas = set()
    for a in args:
        if a.startswith("--"):
            k = _UNAME_LARGAS.get(a[2:])
            if k is None:
                return f"uname: unrecognized option '{a}'\nTry 'uname --help' for more information."
            pedidas.update(_UNAME if k == "a" else k)
        elif a.startswith("-") and len(a) > 1:
            for c in a[1:]:
                if c == "a":
                    pedidas.update(_UNAME)
                elif c in _UNAME:
                    pedidas.add(c)
                else:
                    return f"uname: invalid option -- '{c}'\nTry 'uname --help' for more information."
        else:
            return f"uname: extra operand '{a}'\nTry 'uname --help' for more information."
    if not pedidas:
        pedidas = {"s"}
    return " ".join(_UNAME[c] for c in "snrvmpio" if c in pedidas)

def _codigo(respuesta):
    """Codigo de salida que tendria esa respuesta."""
    if respuesta is None:
        return 0
    respuesta = respuesta.rstrip("\n")
    if respuesta.startswith("bash: ") and respuesta.endswith("command not found"):
        return 127
    if respuesta.startswith(("bash: ./", "bash: /")):
        return 127      # binario con ruta que no existe
    if respuesta.startswith(("bash: ", "uname: ", "sh: ")):
        return 1        # otros errores
    return 0

# Lo que es propio de cada proceso de shell: un "sh -c" no ve las funciones, los
# parametros ni las variables de quien lo llamo, y tiene su propio PID.
_CONTEXTO = ("params", "funcs", "vars", "pid", "dialecto", "nivel_func")

def _subshell(cmd, ip, usuario, estado):
    """sh -c 'comando', bash -c 'comando'. Sin -c no hay script que correr."""
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return "bash: unexpected EOF while looking for matching quote"
    nombre = tokens[0]
    if "-c" not in tokens:
        archivos = [t for t in tokens[1:] if not t.startswith("-")]
        if not archivos:
            return ""
        if nombre in ("sh", "dash"):
            return f"sh: 0: Can't open {archivos[0]}"
        return f"bash: {archivos[0]}: No such file or directory"
    i = tokens.index("-c")
    if i + 1 >= len(tokens):
        return f"{nombre}: -c: option requires an argument"
    if estado.get("prof", 0) >= MAX_PROFUNDIDAD:
        return ""
    guardado = {k: estado.pop(k) for k in _CONTEXTO if k in estado}
    estado["prof"] = estado.get("prof", 0) + 1
    estado["pid"] = shell_interp.nuevo_pid(estado)       # cada sh -c es un proceso nuevo
    estado["dialecto"] = "dash" if nombre in ("sh", "dash") else "bash"
    try:
        r = get_response(tokens[i + 1], ip, usuario, estado)
        codigo = estado.get("codigo", 0)
    finally:
        estado["prof"] -= 1
        for k in _CONTEXTO:
            estado.pop(k, None)
        estado.update(guardado)
    estado.pop("salir", None)   # un exit dentro de sh -c no cierra la sesion
    return shell_interp.Exacto("" if r is None else r, codigo)

def _clasico(ip, usuario, estado):
    """Ejecuta UN comando suelto con la shell clasica: (respuesta, codigo de salida)."""
    def ejecutar(raw):
        r = _ejecutar(raw, ip, usuario, estado)
        if isinstance(r, shell_interp.Exacto):
            return r, r.codigo
        return r, _codigo(r)
    return ejecutar

def get_response(comando, ip, usuario="root", estado=None):
    """Salida EXACTA de una orden: uno o varios comandos encadenados con ; && || o
    saltos de linea, con funciones, printf y aritmetica (ver shell_interp.py). Incluye los
    saltos de linea finales, asi un printf sin \\n no termina en salto, igual que en Linux.
    None significa que el atacante pidio cerrar la sesion; si el exit llega despues de
    otros comandos, se devuelve su salida y estado["salir"] queda en True.
    estado["codigo"] guarda el codigo de salida del ultimo comando."""
    if estado is None:
        estado = {"cwd": _home(usuario)}
    salida = shell_interp.ejecutar(comando.strip(), _clasico(ip, usuario, estado), estado)
    if estado.get("salir") and not salida:
        return None
    return salida


# --- Autenticacion creible -------------------------------------------------
# Un servidor real no deja pasar a la primera con cualquier clave. Aceptamos si:
#  - la clave es una de las debiles tipicas, o
#  - esa IP ya fallo INTENTOS_PARA_ACEPTAR - 1 veces en los ultimos 10 minutos.
# Los intentos rechazados se registran igual (alimentan las reglas de Wazuh).
INTENTOS_PARA_ACEPTAR = 3
VENTANA_SEG = 600
_fallos = {}
_fallos_lock = threading.Lock()

def _debe_aceptar(ip, password):
    ahora = datetime.now().timestamp()
    with _fallos_lock:
        for k in [k for k, v in _fallos.items() if ahora - v[1] > VENTANA_SEG]:
            del _fallos[k]
        if password in CLAVES_DEBILES:
            _fallos.pop(ip, None)
            return True
        n = _fallos.get(ip, (0, ahora))[0] + 1
        if n >= INTENTOS_PARA_ACEPTAR:
            _fallos.pop(ip, None)
            return True
        _fallos[ip] = (n, ahora)
        return False

class FakeShell(paramiko.ServerInterface):
    """Servidor SSH que acepta el login y abre una shell falsa."""
    
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()
        self.intentos = 0
        self.autenticado = False
        self.exec_command = None

    def check_auth_password(self, username, password):
        # Guardar el intento de login (siempre, aunque se rechace)
        from logger import save_attempt
        save_attempt(self.client_ip, username, password)

        self.username = username
        self.intentos += 1
        if _debe_aceptar(self.client_ip, password):
            self.autenticado = True
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"
    
    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True
    
    def check_channel_exec_request(self, channel, command):
        # Comando directo (ssh host "uname -a"), sin sesion interactiva. Es lo que usan
        # los bots: autentican, mandan un comando y se van. Sin este metodo paramiko
        # lo rechaza y ese comando no queda registrado.
        if isinstance(command, bytes):
            command = command.decode("utf-8", errors="replace")
        self.exec_command = command
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


def _ultimo_login(client_ip):
    """Un 'Last login' creible: fecha anterior e IP distinta a la del cliente actual.
    Es determinista por IP, asi un atacante que reconecta ve siempre lo mismo."""
    h = int(hashlib.md5(client_ip.encode()).hexdigest(), 16)
    fecha = datetime.now() - timedelta(days=1 + h % 6, hours=(h >> 8) % 24, minutes=(h >> 16) % 60)
    origen = f"10.0.{(h >> 24) % 250 + 1}.{(h >> 32) % 250 + 1}"
    return fecha.strftime("%a %b %d %H:%M:%S %Y"), origen

MAX_EXEC_LARGO = 4096   # caracteres que se procesan de un comando exec

def manejar_exec(channel, client_ip, username, comando):
    """Responde a un comando directo (canal exec): lo ejecuta con el mismo interprete falso
    que la shell interactiva, devuelve la salida y cierra el canal."""
    usuario = re.sub(r"[^A-Za-z0-9_.-]", "", str(username))[:32] or "user"
    comando = comando[:MAX_EXEC_LARGO]
    estado = {"cwd": _home(usuario), "canal": "exec"}

    # Se guarda el comando entero una vez, tal cual llego
    save_command(client_ip, comando, "Comando por canal exec", canal="exec")

    respuesta = get_response(comando, client_ip, usuario, estado) or ""
    try:
        if respuesta:
            # Sin pty las salidas terminan en \n (no \r\n). La respuesta ya trae su salto final.
            channel.send(respuesta.replace("\r\n", "\n").encode())
        channel.send_exit_status(estado.get("codigo", 0))
    except Exception:
        pass
    finally:
        channel.close()

def manejar_shell(channel, client_ip, username):
    """Maneja la sesión interactiva de la shell falsa."""
    # El prompt usa el usuario con el que entro (el atacante lo ve coherente con whoami)
    usuario = re.sub(r"[^A-Za-z0-9_.-]", "", str(username))[:32] or "user"
    estado = {"cwd": _home(usuario)}
    prompt = _prompt(usuario, estado)
    ultima_fecha, ultimo_origen = _ultimo_login(client_ip)
    
    # Mensaje de bienvenida — igual al de Ubuntu real
    bienvenida = f"""Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-1034-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Last login: {ultima_fecha} from {ultimo_origen}
"""
    # Las terminales necesitan \r\n; con solo \n el texto sale escalonado
    channel.send(bienvenida.replace("\n", "\r\n").encode())
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
                        respuesta = get_response(comando_actual.strip(), client_ip, usuario, estado)
                        
                        # None, o estado["salir"], significa que pidió exit
                        salir = respuesta is None or estado.pop("salir", False)

                        if respuesta:
                            channel.send(respuesta.replace("\r\n", "\n").replace("\n", "\r\n").encode())

                        if salir:
                            channel.send(b"logout\r\n")
                            channel.close()
                            return
                    
                    comando_actual = ""
                    prompt = _prompt(usuario, estado)
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