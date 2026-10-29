"""Entradas al azar contra la shell falsa.

El atacante controla cada caracter que entra aca, asi que lo minimo es: ninguna entrada
rompe el programa (una excepcion mataria el hilo de esa conexion) y ninguna tarda de mas.
La semilla es fija para que, si algo falla, el caso se pueda reproducir.
"""
import random
import time

import pytest

import fake_shell

PIEZAS = [
    "echo", "printf", "set", "--", "shift", "sh", "-c", "f", "()", "{", "}", ";", "&&", "||",
    "|", ">", "<", "&", "'", '"', "\\", "$", "$$", "$#", "$1", "$?", "$((", "))", "(", ")",
    "1", "2", "0", "+", "*", "/", "%", "**", "<<", "`", "$(", "\n", " ", " ", "  ", "%s", "%d",
    "%5s", "\\n", "exit", "cd", "ls", "uname", "wget", "http://203.0.113.1/x", "A=1", "$A", "a", "b",
]


@pytest.mark.parametrize("semilla", range(5))
def test_ninguna_entrada_al_azar_rompe_la_shell(semilla):
    azar = random.Random(semilla)
    peor = 0.0
    for _ in range(2000):
        orden = "".join(azar.choice(PIEZAS) for _ in range(azar.randint(1, 18)))
        inicio = time.perf_counter()
        try:
            r = fake_shell.get_response(orden, "203.0.113.7", "root", {"cwd": "/root"})
        except Exception as e:                                  # pragma: no cover
            pytest.fail(f"{type(e).__name__}: {e} con la orden {orden!r}")
        assert r is None or isinstance(r, str)
        peor = max(peor, time.perf_counter() - inicio)
    assert peor < 0.5, f"una orden tardo {peor:.2f}s"


def test_orden_enorme_no_cuelga_la_shell():
    inicio = time.perf_counter()
    fake_shell.get_response("echo " + "$((1+" * 500 + "1" + "))" * 500, "203.0.113.7", "root", {"cwd": "/root"})
    fake_shell.get_response("f() { f; f; f; }; f", "203.0.113.7", "root", {"cwd": "/root"})
    fake_shell.get_response("printf '%s' " + "a " * 5000, "203.0.113.7", "root", {"cwd": "/root"})
    assert time.perf_counter() - inicio < 2
