# Changelog

Dates are real. Every change that can alter what an attacker sees is marked, because the measurement window only means something if the honeypot does not change under it.

Las fechas son reales. Cada cambio que puede alterar lo que ve un atacante está marcado, porque la ventana de medición solo sirve si el honeypot no cambia mientras corre.

## 2026-10-30 (prepared, NOT deployed yet / preparado, SIN desplegar todavía)

Does not change what an attacker sees (paramiko stays on 4.0.0, and the SSH handshake the server sends is identical under the old and the new `cryptography`), but it needs `docker compose build` and `up -d`, which restarts the container and cuts live connections for a few seconds. When it is deployed, add the real date and time here and note the restart in the measurement window.
No cambia lo que ve un atacante (paramiko sigue en la 4.0.0, y el handshake SSH que manda el servidor es idéntico con el `cryptography` viejo y el nuevo), pero requiere `docker compose build` y `up -d`, que reinicia el contenedor y corta las conexiones en curso unos segundos. Cuando se despliegue, anotar acá la fecha y hora reales y el reinicio dentro de la ventana de medición.

### Added / Agregado
- Dashboard login (`dashboard_auth.py`): one password from `DASHBOARD_PASSWORD`, session cookie, websocket included, lockout after five failures. Without the password the dashboard is locked (503). **Before deploying, add `DASHBOARD_PASSWORD` to the `.env` on the honeypot server**, or the dashboard stays locked after the restart. 32 tests.
  Login del dashboard (`dashboard_auth.py`): una contraseña desde `DASHBOARD_PASSWORD`, cookie de sesión, websocket incluido, bloqueo tras cinco fallos. Sin contraseña el dashboard queda bloqueado (503). **Antes de desplegar, agregar `DASHBOARD_PASSWORD` al `.env` del servidor del honeypot**, o el dashboard queda bloqueado después del reinicio. 32 tests.
- GitHub Actions: `pytest` and `pip-audit` on every push, pull request and every Monday. The accepted exception is CVE-2026-44405.
  GitHub Actions: `pytest` y `pip-audit` en cada push, pull request y todos los lunes. La excepción aceptada es CVE-2026-44405.

### Changed / Cambiado
- The dashboard cookie signing key is no longer a fixed string in the code (it comes from `DASHBOARD_SECRET_KEY` or is random at each start), and the websocket no longer accepts any origin.
  La clave que firma las cookies del dashboard ya no es un texto fijo en el código (sale de `DASHBOARD_SECRET_KEY` o es aleatoria en cada arranque), y el websocket ya no acepta cualquier origen.
- Eight dependencies moved to fixed versions after the first `pip-audit`: certifi, cryptography (46.0.6 to 50.0.2), filelock, idna, python-engineio, python-socketio, urllib3, Werkzeug. The tests pass on the new versions; the rebuilt container has not run yet.
  Ocho dependencias pasaron a versiones corregidas tras el primer `pip-audit`: certifi, cryptography (de 46.0.6 a 50.0.2), filelock, idna, python-engineio, python-socketio, urllib3, Werkzeug. Los tests pasan con las versiones nuevas; el contenedor reconstruido todavía no corrió.

## 2026-10-29 (analysis tooling, no container change / herramienta de análisis, sin cambios en el contenedor)

Does not change what an attacker sees and does not need a redeploy: the script runs on the host, outside the container, and only reads the logs. The measurement window keeps running.
No cambia lo que ve un atacante ni requiere volver a desplegar: el script corre en el host, fuera del contenedor, y solo lee los logs. La ventana de medición sigue corriendo.

### Added / Agregado
- `resumen_diario.py`: daily report with masked IPs, history of recurring IPs and triage flags, plus 18 tests. It supports a routine of daily analysis and hypotheses (new vs. recurring IPs, one attempt per visit across days, authenticated-then-left).
  `resumen_diario.py`: informe diario con IPs enmascaradas, historial de las IPs recurrentes y banderas de triage, más 18 tests. Apoya una rutina de análisis y de hipótesis a diario (IPs nuevas frente a recurrentes, un intento por visita a lo largo de los días, autenticó y se fue).

## 2026-10-29 (deployed to the honeypot / desplegado en el honeypot)

**Measurement window starts / Inicio de la ventana de medición: 2026-10-29 20:03:21 UTC (17:03:21 ART).**
From this moment the honeypot has the interpreter, the hardened container and paramiko 4.0.0. It should not change until the window closes.
Desde este momento el honeypot tiene el intérprete, el contenedor endurecido y paramiko 4.0.0. No debería cambiar hasta que se cierre la ventana.

Own test traffic is logged from `172.18.0.1` (the Docker gateway, the honeypot's own host). Ignore that IP when analyzing the window.
El tráfico de prueba propio queda registrado desde `172.18.0.1` (la puerta de enlace de Docker, el propio host del honeypot). Hay que ignorar esa IP al analizar la ventana.

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

## Baseline / Línea base (2026-10-26 to 2026-10-29 19:58 UTC)

Data collected with the original fake shell, before it learned `printf`, shell arithmetic and `$$`. Kept as the "before" for a comparison now that the shell is updated. A copy of the logs from that moment lives on the honeypot server, outside the repo (`~/linea_base_2026-10-29`).
Datos recolectados con la shell falsa original, antes de que aprendiera `printf`, aritmética de shell y `$$`. Se conservan como el "antes" para comparar ahora que la shell está actualizada. Una copia de los logs de ese momento está en el servidor del honeypot, fuera del repo (`~/linea_base_2026-10-29`).
