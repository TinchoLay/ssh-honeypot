"""Intérprete mínimo de shell para la shell falsa del honeypot.

Por qué existe: los bots que perfilan el servidor ya no preguntan "¿existe tal archivo?".
Mandan un script chico (printf, aritmética, $$, set --, una función) y comprueban que el
intérprete CALCULE de verdad. Una shell que responde "command not found" a un printf
se delata sola. Este módulo entiende lo justo para pasar esa prueba.

Seguridad, lo más importante de este archivo:
  * NUNCA se usa eval, exec, os.system ni subprocess. El texto del atacante nunca llega
    a un intérprete real: se lo recorre carácter por carácter y se lo reduce a datos.
  * La aritmética se evalúa recorriendo el árbol de ast con una lista blanca de
    operadores (ver _evaluar). No hay nombres, llamadas ni atributos.
  * Todo está acotado: largo de expresión, exponentes, desplazamientos, cantidad de
    comandos por lista, cantidad total de pasos y profundidad de funciones.

Lo que NO hace (a propósito): pipes, redirecciones, sustitución de comandos $( ), bucles,
if/case. Un comando con esos operadores se le pasa tal cual a la shell "clásica" de
fake_shell.py, que ya los trata a su manera.

Contrato: ejecutar() devuelve la salida EXACTA del comando, con sus saltos de línea
(por eso un printf sin \\n no termina en salto, igual que en un Linux real).
"""
import ast
import random
import re

MAX_PARTES = 20          # comandos por lista (igual que antes en fake_shell)
MAX_PASOS = 200          # comandos en total por orden, contando llamadas a funciones
MAX_NIVEL_FUNC = 8       # funciones que llaman a funciones
MAX_EXPR = 200           # largo de una expresión aritmética
MAX_PRINTF = 20000       # caracteres de salida de un printf (frena `printf "%s" ...` enormes)

_FUNC = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{(.*)\}\s*$", re.DOTALL)
_ASIGNACION = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.DOTALL)
_NOMBRE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


# --- Partir una orden en comandos ------------------------------------------------

def _llave(texto, i, cual):
    """True si la llave en texto[i] es una llave de agrupación ('{ ... }') y no
    parte de otra cosa como ${1}. Tiene que ir sola, rodeada de espacios o ';'."""
    antes = texto[i - 1] if i > 0 else " "
    despues = texto[i + 1] if i + 1 < len(texto) else " "
    if cual == "{":
        return antes in " \t\n;" and despues in " \t\n"
    return antes in " \t\n;" and despues in " \t\n;&|"


def partir(texto):
    """Parte en [(operador, comando)] por ; && || y saltos de línea, sin cortar lo que
    está entre comillas ni dentro de llaves { ... } (el cuerpo de una función)."""
    partes, buf, op, comilla, prof, i, n = [], [], ";", None, 0, 0, len(texto)
    while i < n:
        c = texto[i]
        if comilla:
            buf.append(c)
            if c == comilla:
                comilla = None
            elif c == "\\" and comilla == '"' and i + 1 < n:
                i += 1
                buf.append(texto[i])
        elif c in "'\"":
            comilla = c
            buf.append(c)
        elif c == "\\" and i + 1 < n:
            buf.append(c)
            i += 1
            buf.append(texto[i])
        elif c == "{" and _llave(texto, i, "{"):
            prof += 1
            buf.append(c)
        elif c == "}" and prof and _llave(texto, i, "}"):
            prof -= 1
            buf.append(c)
        elif prof == 0 and c in ";\n":
            partes.append((op, "".join(buf)))
            buf, op = [], ";"
        elif prof == 0 and (texto.startswith("&&", i) or texto.startswith("||", i)):
            partes.append((op, "".join(buf)))
            buf, op = [], texto[i:i + 2]
            i += 1
        else:
            buf.append(c)
        i += 1
    partes.append((op, "".join(buf)))
    return [(o, t.strip()) for o, t in partes if t.strip()]


def _salto_aritmetico(texto, i):
    """Si en texto[i:] empieza $(( ... )), devuelve el índice justo después del '))'
    de cierre. Se cuentan los paréntesis uno por uno: $((1+(2*3))) cierra en el último.
    Si no cierra, devuelve el largo del texto."""
    prof, j = 2, i + 3
    while j < len(texto):
        if texto[j] == "(":
            prof += 1
        elif texto[j] == ")":
            prof -= 1
            if prof == 0:
                return j + 1
        j += 1
    return len(texto)


def _tiene_operador(raw):
    """Detecta lo que este intérprete no entiende, fuera de comillas simples.
    Devuelve "r" si hay pipes, redirecciones o segundo plano (la salida no se ve en pantalla),
    "s" si solo hay sustitución de comandos ($( ) o comillas invertidas), None si no hay nada."""
    comilla, i, n = None, 0, len(raw)
    redireccion = sustitucion = False
    while i < n:
        c = raw[i]
        if comilla == "'":
            if c == "'":
                comilla = None
        elif c == "\\" and i + 1 < n:
            i += 1
        elif raw.startswith("$((", i):
            i = _salto_aritmetico(raw, i) - 1
        elif c == "`" or (c == "$" and raw.startswith("$(", i)):
            sustitucion = True
        elif comilla == '"':
            if c == '"':
                comilla = None
        elif c in "'\"":
            comilla = c
        elif c in "|<>&":
            redireccion = True
        i += 1
    return "r" if redireccion else ("s" if sustitucion else None)


# --- Palabras, comillas y expansiones --------------------------------------------

def _palabras(raw):
    """Divide en palabras. Cada palabra es una lista de (texto, tipo) donde tipo es
    "'" (literal), '"' (se expande, no se parte) o "" (se expande y se parte).
    Devuelve None si queda una comilla sin cerrar."""
    palabras, actual, i, n = [], None, 0, len(raw)
    while i < n:
        c = raw[i]
        if c in " \t\n":
            if actual is not None:
                palabras.append(actual)
                actual = None
            i += 1
        elif c == "'":
            j = raw.find("'", i + 1)
            if j < 0:
                return None
            actual = (actual or []) + [(raw[i + 1:j], "'")]
            i = j + 1
        elif c == '"':
            j, trozo = i + 1, []
            while j < n and raw[j] != '"':
                if raw[j] == "\\" and j + 1 < n and raw[j + 1] in '$`"\\':
                    trozo.append(("\x00" + raw[j + 1]))   # escapado: literal
                    j += 2
                else:
                    trozo.append(raw[j])
                    j += 1
            if j >= n:
                return None
            actual = (actual or []) + [("".join(trozo), '"')]
            i = j + 1
        elif c == "\\" and i + 1 < n:
            actual = (actual or []) + [(raw[i + 1], "'")]
            i += 2
        elif raw.startswith("$((", i):
            fin = _salto_aritmetico(raw, i)
            actual = (actual or []) + [(raw[i:fin], "")]
            i = fin
        else:
            j = i
            while j < n and raw[j] not in " \t\n'\"\\":
                if raw.startswith("$((", j):
                    break
                j += 1
            if j == i:        # un '$((' pegado: lo toma el caso de arriba en la vuelta siguiente
                j = i + 1
            actual = (actual or []) + [(raw[i:j], "")]
            i = j
    if actual is not None:
        palabras.append(actual)
    return palabras


def _pid(estado):
    """PID de la shell en curso. Es un número creíble y estable dentro de la sesión."""
    if "pid" not in estado:
        estado["pid"] = _nuevo_pid(estado)
    return estado["pid"]


def _nuevo_pid(estado):
    """PID para un proceso nuevo (cada 'sh -c' es un proceso distinto). Crece de a poco,
    como en un servidor real, en vez de saltar al azar."""
    base = estado.setdefault("pid_base", random.randint(1800, 31000))
    estado["pid_base"] = base + random.randint(1, 9)
    return estado["pid_base"]


def _valor(nombre, estado):
    """Valor de $nombre (nombre ya sin el $)."""
    params = estado.get("params", [])
    if nombre == "$":
        return str(_pid(estado))
    if nombre == "#":
        return str(len(params))
    if nombre == "?":
        return str(estado.get("codigo", 0))
    if nombre in ("@", "*"):
        return " ".join(params)
    if nombre == "0":
        return "sh"
    if nombre.isdigit():
        k = int(nombre)
        return params[k - 1] if 1 <= k <= len(params) else ""
    return estado.get("vars", {}).get(nombre, "")


def _expandir_texto(texto, estado):
    """Aplica $$ $# $? $1 $nombre ${nombre} y $((expr)) a un trozo de texto.
    Devuelve (texto, error) donde error es None o un mensaje de shell."""
    out, i, n = [], 0, len(texto)
    while i < n:
        c = texto[i]
        if c == "\x00" and i + 1 < n:           # carácter escapado dentro de comillas dobles
            out.append(texto[i + 1])
            i += 2
        elif c != "$":
            out.append(c)
            i += 1
        elif texto.startswith("$((", i):
            fin = _salto_aritmetico(texto, i)
            expr = texto[i + 3:fin - 2] if texto.startswith("))", fin - 2) else texto[i + 3:fin]
            valor, error = _aritmetica(expr, estado)
            if error:
                return "", error
            out.append(str(valor))
            i = fin
        elif i + 1 < n and texto[i + 1] in "$#?@*0123456789":
            out.append(_valor(texto[i + 1], estado))
            i += 2
        elif texto.startswith("${", i) and "}" in texto[i:]:
            j = texto.index("}", i)
            nombre = texto[i + 2:j]
            out.append(_valor(nombre, estado) if (nombre.isdigit() or nombre in ("#", "?", "$", "@", "*")
                                                  or _NOMBRE.fullmatch(nombre)) else "")
            i = j + 1
        else:
            m = _NOMBRE.match(texto, i + 1)
            if m:
                out.append(_valor(m.group(0), estado))
                i = m.end()
            else:
                out.append("$")
                i += 1
    return "".join(out), None


def _campos(palabra, estado):
    """Expande una palabra y la parte en campos. Devuelve (lista de campos, error)."""
    trozos = []
    for texto, tipo in palabra:
        if tipo == "'":
            trozos.append((texto, False))
        else:
            expandido, error = _expandir_texto(texto, estado)
            if error:
                return [], error
            trozos.append((expandido, tipo == ""))
    campos, actual = [], None
    for texto, partible in trozos:
        if not partible:
            actual = (actual or "") + texto
            continue
        for trozo in re.split(r"(\s+)", texto):
            if not trozo:
                continue
            if trozo.isspace():
                if actual is not None:
                    campos.append(actual)
                    actual = None
            else:
                actual = (actual or "") + trozo
    if actual is not None:
        campos.append(actual)
    return campos, None


# --- Aritmética (sin eval) -------------------------------------------------------

_LIMITE = 1 << 63


def _envolver(v):
    """Enteros con signo de 64 bits, como en bash."""
    v &= (1 << 64) - 1
    return v - (1 << 64) if v >= _LIMITE else v


def _evaluar(nodo):
    if isinstance(nodo, ast.Expression):
        return _evaluar(nodo.body)
    if isinstance(nodo, ast.Constant) and type(nodo.value) is int:
        return _envolver(nodo.value)
    if isinstance(nodo, ast.UnaryOp):
        v = _evaluar(nodo.operand)
        if isinstance(nodo.op, ast.USub):
            return _envolver(-v)
        if isinstance(nodo.op, ast.UAdd):
            return v
        if isinstance(nodo.op, ast.Invert):
            return _envolver(~v)
        raise ValueError("operador")
    if isinstance(nodo, ast.BinOp):
        a, b, op = _evaluar(nodo.left), _evaluar(nodo.right), nodo.op
        if isinstance(op, ast.Add):
            return _envolver(a + b)
        if isinstance(op, ast.Sub):
            return _envolver(a - b)
        if isinstance(op, ast.Mult):
            return _envolver(a * b)
        if isinstance(op, (ast.Div, ast.Mod)):
            if b == 0:
                raise ZeroDivisionError
            cociente = abs(a) // abs(b) * (1 if (a < 0) == (b < 0) else -1)   # trunca hacia 0, como C
            return _envolver(cociente if isinstance(op, ast.Div) else a - cociente * b)
        if isinstance(op, ast.Pow):
            if b < 0 or b > 64:
                raise ValueError("exponente")
            return _envolver(a ** b)
        if isinstance(op, (ast.LShift, ast.RShift)):
            if b < 0 or b > 63:
                raise ValueError("desplazamiento")
            return _envolver(a << b if isinstance(op, ast.LShift) else a >> b)
        if isinstance(op, ast.BitAnd):
            return _envolver(a & b)
        if isinstance(op, ast.BitOr):
            return _envolver(a | b)
        if isinstance(op, ast.BitXor):
            return _envolver(a ^ b)
    raise ValueError("expresión no permitida")


def _aritmetica(expr, estado):
    """Evalúa el interior de $(( ... )). Devuelve (valor, None) o (None, mensaje de error)."""
    original = expr.strip()
    fallo = f'sh: 1: arithmetic expression: expecting primary: "{original[:60]}"\n'
    try:
        if len(original) > MAX_EXPR:
            return None, fallo
        expr, error = _expandir_texto(original, estado)
        if error:
            return None, error
        # Los nombres sueltos (a, b) valen lo que tengan las variables, o 0.
        # El lookbehind evita tocar literales como 0x1F.
        vars_ = estado.get("vars", {})

        def valor_var(m):
            v = vars_.get(m.group(0), "0")
            return v if re.fullmatch(r"-?\d+", v or "") else "0"
        expr = re.sub(r"(?<![0-9A-Za-z_])[A-Za-z_][A-Za-z0-9_]*", valor_var, expr)
        if not expr.strip():
            return 0, None
        # Lista blanca de caracteres: aca ya solo pueden quedar numeros y operadores.
        # Comillas, barras, puntos o letras sueltas (cualquier intento de escribir Python)
        # se rechazan antes de llegar al parser.
        if not re.fullmatch(r"[0-9a-fA-FxX\s+\-*/%()<>&|^~]*", expr):
            return None, fallo
        return _evaluar(ast.parse(expr.strip(), mode="eval")), None
    except ZeroDivisionError:
        return None, "sh: 1: arithmetic expression: division by 0\n"
    except (SyntaxError, ValueError, RecursionError, MemoryError, OverflowError):
        return None, fallo


# --- printf y echo ---------------------------------------------------------------

_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "f": "\f", "v": "\v",
            "\\": "\\", '"': '"', "'": "'"}


def _escapes(texto):
    """Interpreta \\n \\t \\\\ \\0NNN y \\xHH como lo hacen printf y echo -e."""
    out, i, n = [], 0, len(texto)
    while i < n:
        c = texto[i]
        if c != "\\" or i + 1 >= n:
            out.append(c)
            i += 1
            continue
        d = texto[i + 1]
        if d in _ESCAPES:
            out.append(_ESCAPES[d])
            i += 2
        elif d in "01234567":
            m = re.match(r"0?([0-7]{1,3})", texto[i + 1:])
            out.append(chr(int(m.group(1), 8) % 256) if m else "")
            i += 1 + (m.end() if m else 1)
        elif d == "x" and re.match(r"[0-9a-fA-F]{1,2}", texto[i + 2:i + 4]):
            m = re.match(r"[0-9a-fA-F]{1,2}", texto[i + 2:i + 4])
            out.append(chr(int(m.group(0), 16)))
            i += 2 + m.end()
        else:
            out.append(c + d)
            i += 2
    return "".join(out)


_CONVERSION = re.compile(r"%(?P<banderas>[-0 +#]*)(?P<ancho>\d*)(?:\.(?P<prec>\d+))?(?P<tipo>[sdibcxXou%])")


def _entero(texto):
    t = texto.strip()
    try:
        if re.fullmatch(r"[-+]?0[xX][0-9a-fA-F]+", t):
            return int(t, 16), True
        if re.fullmatch(r"[-+]?0[0-7]+", t):
            return int(t, 8), True
        return int(t), True
    except ValueError:
        return 0, texto == ""


def _printf(args):
    """printf FORMATO [ARGUMENTOS...]. Devuelve (salida, código de salida)."""
    if not args:
        return "printf: usage: printf format [arguments]\n", 2
    formato = _escapes(args[0])
    valores = args[1:]
    convs = [m for m in _CONVERSION.finditer(formato) if m.group("tipo") != "%"]
    codigo, partes = 0, []

    def una_vuelta(vals):
        nonlocal codigo
        it = iter(vals)

        def reemplazo(m):
            nonlocal codigo
            tipo = m.group("tipo")
            if tipo == "%":
                return "%"
            arg = next(it, None)
            ancho = int(m.group("ancho") or 0)
            izq = "-" in m.group("banderas")
            if tipo in "sb":
                s = "" if arg is None else (_escapes(arg) if tipo == "b" else arg)
                if m.group("prec"):
                    s = s[:int(m.group("prec"))]
            elif tipo == "c":
                s = (arg or "")[:1]
            else:
                n, ok = _entero(arg or "0")
                if not ok:
                    codigo = 1
                s = {"d": str(n), "i": str(n), "u": str(n % (1 << 64)), "x": format(n, "x"),
                     "X": format(n, "X"), "o": format(n, "o")}[tipo]
                if "0" in m.group("banderas") and not izq:
                    return s.rjust(ancho, "0")
            return s.ljust(ancho) if izq else s.rjust(ancho)
        return _CONVERSION.sub(reemplazo, formato)

    if not convs:
        partes.append(una_vuelta([]))
    else:
        i = 0
        while True:
            partes.append(una_vuelta(valores[i:i + len(convs)]))
            i += len(convs)
            if i >= len(valores) or sum(len(p) for p in partes) > MAX_PRINTF:
                break
    return "".join(partes)[:MAX_PRINTF], codigo


def _echo(args, estado):
    sin_salto, interpretar = False, estado.get("dialecto") == "dash"
    while args and re.fullmatch(r"-[neE]+", args[0]):
        sin_salto = sin_salto or "n" in args[0]
        if "e" in args[0]:
            interpretar = True
        if "E" in args[0]:
            interpretar = False
        args = args[1:]
    texto = " ".join(args)
    if interpretar:
        texto = _escapes(texto)
    return texto + ("" if sin_salto else "\n")


# --- Ejecución -------------------------------------------------------------------

def ejecutar(texto, clasico, estado):
    """Ejecuta una orden (uno o varios comandos encadenados). `clasico(raw)` ejecuta un
    comando suelto con la shell clásica y devuelve (respuesta o None, código); None
    significa exit. Devuelve la salida exacta."""
    if not estado.get("prof"):
        estado["pasos"] = 0
    return _lista(texto, clasico, estado, 0)


def _lista(texto, clasico, estado, nivel):
    salida, fallo = [], False
    for op, raw in partir(texto)[:MAX_PARTES]:
        if estado.get("salir"):
            break
        if (op == "&&" and fallo) or (op == "||" and not fallo):
            continue
        out, codigo = _comando(raw, clasico, estado, nivel)
        salida.append(out)
        estado["codigo"] = codigo
        fallo = codigo != 0
    return "".join(salida)


def _comando(raw, clasico, estado, nivel):
    estado["pasos"] = estado.get("pasos", 0) + 1
    if estado["pasos"] > MAX_PASOS:
        return "", 1
    raw = raw.strip()
    if not raw:
        return "", 0

    m = _FUNC.match(raw)
    if m:
        estado.setdefault("funcs", {})[m.group(1)] = m.group(2)
        return "", 0
    if raw.startswith("{") and raw.endswith("}") and _llave(raw, 0, "{"):
        return _lista(raw[1:-1], clasico, estado, nivel), estado.get("codigo", 0)

    tipo_operador = _tiene_operador(raw)
    if tipo_operador:
        # Pipes, redirecciones, $( ): este intérprete no los entiende. Si es una
        # redireccion de un comando propio, su salida iría a un archivo o a otro comando
        # y no se vería; en cualquier otro caso se lo pasa tal cual a la shell clásica.
        crudas = _palabras(raw)
        if tipo_operador == "r" and crudas and _primer_nombre(crudas) in _PROPIOS:
            return "", 0
        return _clasico(raw, clasico, estado)
    palabras = _palabras(raw)
    if palabras is None:            # comilla sin cerrar: que decida la shell clásica
        return _clasico(raw, clasico, estado)

    campos = []
    for palabra in palabras:
        c, error = _campos(palabra, estado)
        if error:
            return error, 2
        campos.extend(c)

    # VAR=valor [comando]: solo asignaciones, o asignaciones y después un comando
    i = 0
    while i < len(campos) and _ASIGNACION.match(campos[i]) and palabras[i] and palabras[i][0][1] == "":
        i += 1
    if i:
        for a in campos[:i]:
            k, v = _ASIGNACION.match(a).groups()
            estado.setdefault("vars", {})[k] = v
        campos = campos[i:]
        if not campos:
            return "", 0

    if not campos:                  # por ejemplo "$variable_vacia": no hace nada
        return "", 0
    nombre, args = campos[0], campos[1:]
    funcs = estado.get("funcs", {})
    if nombre in funcs:
        if estado.get("nivel_func", 0) >= MAX_NIVEL_FUNC:
            return "", 1
        guardado = estado.get("params", [])
        estado["params"] = list(args)
        estado["nivel_func"] = estado.get("nivel_func", 0) + 1
        try:
            out = _lista(funcs[nombre], clasico, estado, nivel + 1)
        finally:
            estado["nivel_func"] -= 1
            estado["params"] = guardado
        return out, estado.get("codigo", 0)
    if nombre == "printf":
        out, codigo = _printf(args)
        return out, codigo
    if nombre == "echo":
        return _echo(args, estado), 0
    if nombre == "set":
        if args[:1] == ["--"]:
            estado["params"] = list(args[1:])
        return "", 0
    if nombre == "shift":
        k = int(args[0]) if args and args[0].isdigit() else 1
        params = estado.get("params", [])
        if k > len(params):
            return "sh: 1: shift: can't shift that many\n", 2
        estado["params"] = params[k:]
        return "", 0
    if nombre in (":", "true"):
        return "", 0
    if nombre == "false":
        return "", 1
    if nombre in ("exit", "logout"):
        estado["salir"] = True
        return "", int(args[0]) % 256 if args and args[0].lstrip("-").isdigit() else estado.get("codigo", 0)
    return _clasico(raw, clasico, estado)


_PROPIOS = {"printf", "echo", "set", "shift", ":", "true", "false"}


def _primer_nombre(palabras):
    """Nombre del comando sin expandir, para decidir si una redirección se traga la salida."""
    return "".join(t for t, _ in palabras[0]) if palabras else None


class Exacto(str):
    """Salida que ya es exacta (termina como terminaría en un Linux real) y que trae el
    código de salida real. La produce sh -c, a diferencia de los comandos sueltos, cuya
    respuesta no incluye el salto de línea final."""
    def __new__(cls, texto, codigo=0):
        obj = super().__new__(cls, texto)
        obj.codigo = codigo
        return obj


def nuevo_pid(estado):
    return _nuevo_pid(estado)


def _clasico(raw, clasico, estado):
    """Delega en la shell clásica. None = el atacante pidió cerrar la sesión."""
    r, codigo = clasico(raw)
    if r is None:
        estado["salir"] = True
        return "", 0
    if isinstance(r, Exacto):
        return str(r), codigo
    return (r + "\n" if r else ""), codigo
