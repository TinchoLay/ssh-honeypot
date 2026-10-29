# Changelog

Dates are real. Every change that can alter what an attacker sees is marked, because the measurement window only means something if the honeypot does not change under it.

Las fechas son reales. Cada cambio que puede alterar lo que ve un atacante está marcado, porque la ventana de medición solo sirve si el honeypot no cambia mientras corre.

## Unreleased (prepared 2026-10-29, not deployed yet / sin desplegar todavía)

### Changes what an attacker sees / Cambia lo que ve un atacante
- The fake shell now answers the shell capability check that bots send (`printf` with a marker, `$((a*b+c))`, `$$`, `set --`, a function): new `shell_interp.py`, no `eval`. Before, all of it returned `command not found`. Output is now exact, including the final newline (`printf abc` no longer gets one added).
  La shell falsa ahora responde la verificación de capacidades que mandan los bots (`printf` con marcador, `$((a*b+c))`, `$$`, `set --`, una función): nuevo `shell_interp.py`, sin `eval`. Antes todo eso devolvía `command not found`. La salida ahora es exacta, con el salto de línea final (a `printf abc` ya no se le agrega uno).
- Each `sh -c` has its own PID and does not see the caller's functions or parameters.
  Cada `sh -c` tiene su propio PID y no ve las funciones ni los parámetros de quien lo llamó.

### Added / Agregado
- Test suite with pytest: fake shell, login rules, exec channel and an end-to-end SSH session. The real bot probe is a fixture, and a seeded fuzz test checks that no input crashes or stalls the shell.
  Suite de tests con pytest: shell falsa, reglas de login, canal exec y una sesión SSH de punta a punta. El examen real del bot es un fixture, y un test de fuzzing con semilla comprueba que ninguna entrada rompa o cuelgue la shell.

### Changed / Cambiado
- Container hardening: unprivileged user, read-only filesystem with `tmpfs` on `/tmp`, `cap_drop: ALL`, `no-new-privileges`, process and memory limits. Does not change what an attacker sees. The `logs/` folder on the host must belong to UID 10001.
  Endurecimiento del contenedor: usuario sin privilegios, sistema de archivos de solo lectura con `tmpfs` en `/tmp`, `cap_drop: ALL`, `no-new-privileges`, límites de procesos y memoria. No cambia lo que ve un atacante. La carpeta `logs/` del host tiene que pertenecer al UID 10001.

### Decided / Decidido
- paramiko stays on 4.0.0 (CVE-2026-44405 accepted as an exception, reasons in the README). Version 5.x would stop old SHA-1-only clients from connecting, and those are traffic this honeypot wants to see.
  paramiko se queda en la 4.0.0 (CVE-2026-44405 aceptado como excepción, los motivos están en el README). La 5.x impediría conectarse a los clientes viejos que solo hablan SHA-1, y ese es tráfico que este honeypot quiere ver.

## Baseline / Línea base (2026-10-26 to 2026-10-28)

Data collected with the original fake shell, before it learned `printf`, shell arithmetic and `$$`. Kept as the "before" for a comparison once the shell is updated.
Datos recolectados con la shell falsa original, antes de que aprendiera `printf`, aritmética de shell y `$$`. Se conservan como el "antes" para comparar cuando la shell se actualice.
