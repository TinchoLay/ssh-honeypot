# SSH Honeypot

[![CI](https://github.com/TinchoLay/ssh-honeypot/actions/workflows/ci.yml/badge.svg)](https://github.com/TinchoLay/ssh-honeypot/actions/workflows/ci.yml)

**[English](#english) | [Español](#español)**

---

## English

A honeypot is a decoy server. It looks real and accepts connections, but there is nothing of value inside. Its only job is to attract attackers and log what they do. This project fakes three services (SSH, HTTP and FTP). It first ran on an Azure VM and now runs in Docker on AWS EC2, exposed to the internet and taking traffic from real attackers. A Wazuh agent ships its logs to a Wazuh manager, where [custom detection rules](https://github.com/TinchoLay/wazuh-detection-pack/tree/main/honeypot) turn them into alerts.

This is a learning project. The honeypot only captures traffic aimed at a server I own.

### What it does

Someone connects to one of the open ports, thinking they found a real server. The honeypot lets them in, records the username and password they tried and looks up where the IP comes from. From there:

- A machine learning model guesses what kind of attacker it is: a bot going through thousands of combinations, or someone slower who is aiming at this server.
- It reads the banner the SSH client sends on connect, which often gives away the tool (Hydra, Metasploit, a home-made script).
- If the attacker tries `wget` or `curl`, the honeypot lets them think it worked and downloads the real file in the background to analyze it.
- It checks the IP against AbuseIPDB and Shodan.
- Everything shows up live on a web dashboard.

### The three fake services

- **SSH (2222, and 22 through a port forward):** the most built-out one. It opens a fake interactive shell that imitates Ubuntu 22.04. The attacker can type `ls`, `cd`, `whoami` or `cat /etc/passwd` and gets plausible answers. Everything they type is logged. It also answers commands sent in one go (`ssh host "uname -a"`), which automated tools commonly use instead of opening a session.
- **HTTP (8080):** a fake admin panel styled after a TP-Link router. It catches scanners looking for poorly secured admin pages. It stores the method, path, headers and POST body.
- **FTP (2121):** accepts the connection and rejects every credential. It shows which usernames and passwords get tried there.

### Making it harder to spot

A honeypot that is easy to recognize only collects traffic from the laziest bots. I made these changes after thinking about how a scanner would fingerprint it:

- **Persistent host key.** It used to generate a new key on every start, which is the kind of thing a returning scanner notices. The key now lives in `logs/` and survives restarts.
- **Full banner.** The SSH version string matches a real Ubuntu 22.04 OpenSSH build.
- **Believable authentication.** The login is accepted if the password is in a list of weak and default credentials (`weak_passwords.py`, 69 entries from common password lists and IoT defaults), or on the third attempt from the same IP within 10 minutes. A server that accepts everything on the first try looks fake.
- **A shell that remembers where you are.** `cd`, `pwd` and `ls` work against a small fake filesystem. A fresh home directory is empty, `ls -la` shows the dotfiles, `/` lists the usual directories and `/root` gives "Permission denied" to normal users. The prompt follows the current directory.
- **Per-user output.** `whoami`, `id` and the "Last login" line match the user who logged in.
- **Error messages like bash's.** `echo "..." >> file` prints nothing, and running a path that does not exist (`./x.sh`) answers "No such file or directory" instead of "command not found".

These are my own measures against fingerprinting. I have not tested them against a scanner built to detect honeypots, so I do not claim the honeypot is undetectable.

### How attacker classification works

A Random Forest trained on the data the honeypot captures, retrained automatically every 100 attempts. It sorts attackers into four groups:

- `bot_fuerza_bruta`: automated scripts going through credentials at high speed
- `scanner`: sweeping ports and services without trying to break into anything specific
- `script_kiddie`: using known tools such as Hydra without much strategy
- `atacante_dirigido`: slower and more human, seemingly aimed at this server

### Malware analysis

When someone pulls a file, the honeypot downloads it in the background, computes its MD5 and SHA256 and checks the hash against VirusTotal. The result is saved with the number of engines that flagged it. Wazuh rule 100320 fires when at least one engine does.

### Dashboard

A Flask and WebSockets panel that updates when a new attack arrives. Three tabs:

- **Stats:** totals per protocol, most tried usernames and passwords, countries of origin and a live log.
- **Analysis:** charts of attacks by hour of day and day of week, and where from.
- **Map:** every SSH, HTTP and FTP event on a world map, with two filters that combine. Type: all, SSH, HTTP or FTP. Period: last hour, 24 hours, 3 days, week, month or since the beginning. So "FTP in the last 24 hours" is one click each.

The map uses OpenStreetMap tiles. I first used CARTO tiles and they started asking for an API key, which turned the map into an error message. Updates are debounced by 1.5 seconds, because with port 22 open every event reloaded the logs and re-sent everything, and the cost grew with each connection.

The dashboard listens on `127.0.0.1:5000` only. It is not exposed to the internet, so reach it through an SSH tunnel.

![Stats tab, captured at 51 events from 21 unique IPs](assets/01-dashboard-stats.png)

![Analysis tab: attacks by hour of day, day of the week, top countries and timeline](assets/02-dashboard-analysis.png)

![Map tab: attack origins on a world map](assets/03-attack-map.png)

![The honeypot starting up: SSH on 2222, HTTP on 8080, FTP on 2121, dashboard on 5000](assets/04-startup-terminal.png)

![HTTP requests in the live log](assets/05-http-requests.png)

### Detection with Wazuh

The honeypot writes one JSON line per event and a Wazuh agent on the same machine ships it to a manager. The rules (SSH brute force fast and slow, how each SSH connection ended, commands typed by the attacker, download attempts, VirusTotal hits, GPON exploit paths, open proxy probes, scanner targets, anonymous FTP) live in the [wazuh-detection-pack](https://github.com/TinchoLay/wazuh-detection-pack/tree/main/honeypot) repository, with the tests I ran and what I could not verify.

### Using port 22

Scanners try port 22 first, so a honeypot that only listens on 2222 sees little. The admin `sshd` on this machine stays on 22, key-only. To catch the traffic I forward port 22 to the container with a DNAT rule in the `nat` table. The rule skips the network I administer the machine from, so the real `sshd` stays reachable for me and for nobody else:

```bash
CIP=$(sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh-honeypot)
sudo iptables -t nat -A PREROUTING ! -s ADMIN_NET -p tcp --dport 22 -j DNAT --to-destination $CIP:2222
```

Replace `ADMIN_NET` with the IP or range you connect from (for example `203.0.113.0/24`).

Three details cost me time:

- **Without the exclusion you lock yourself out.** A DNAT on every source sends your own administration to the honeypot too. With the exclusion, if your IP leaves that range you are locked out of the admin `sshd`. My way back is a reboot (the rule does not persist) or EC2 Instance Connect.

- **Why DNAT and not a redirect to 2222.** Port 2222 is published by Docker through `docker-proxy`. If you redirect to that port, every attacker reaches the container as the bridge address and the real source IP is lost. That breaks the geolocation and every detection that counts attempts per IP. DNAT straight to the container address keeps the source.
- **The rule does not survive a reboot, and the container address can change after a rebuild.** After `docker compose up --build`, delete the old rule (`iptables -t nat -D PREROUTING <n>`) and add it again with the new address. After a reboot the real `sshd` answers on 22 again, which is the safe way to fail.

The security group has to allow port 22 inbound, and then anyone on the internet can reach that port. Do this only on a machine built for it.

To test the honeypot on port 22, connect from outside the excluded range (I use mobile data). From inside it you reach the real `sshd`. Connecting to the same IP from both sides also triggers a "host key changed" warning, because the two services have different host keys.

### Every SSH connection, and commands sent without a shell

Port 22 brings many connections that never try a password, so counting login attempts hides most of what happens. `connection_logger.py` writes one line per SSH connection to `logs/ssh_connections.json`, with how it ended:

| Result | Meaning |
|---|---|
| `sin_banner` | Connected and closed without sending an SSH banner. Typical of port scanners |
| `error_protocolo` | Sent a banner, but the SSH negotiation failed |
| `sin_autenticacion` | Negotiated SSH and never tried to log in |
| `login_fallido` | Tried to log in and was rejected |
| `autenticado_sin_shell` | Got in and never asked for a shell or a command |
| `exec` | Got in and sent a single command (`ssh host "uname -a"`) |
| `shell` | Got in and opened an interactive shell |

Each line also has the client banner, the duration, the number of login attempts and, for `exec`, the command in `detalle`. IPs listed in `HONEYPOT_IGNORE_IPS` are skipped. Docker logs rotate (10 MB, 3 files) so scanner noise cannot fill the disk, and the paramiko tracebacks for dropped connections are silenced because the event is already recorded here.

The first week with port 22 open (19 to 26 October, 2,873 connections) ended like this: 1,250 `login_fallido`, 802 `autenticado_sin_shell`, 669 `sin_banner`, 78 `error_protocolo`, 71 `sin_autenticacion` and only 3 `shell`. The three `autenticado_sin_shell` lines I looked at all came from `SSH-2.0-Go` clients and made one login attempt.

That number made me read my own code. The honeypot only reacted to interactive shell requests. A client that sends a command directly was refused by paramiko's default, so its command was never recorded. I do not know yet how many of those 802 connections sent one. On 26 October I added support:

- `check_channel_exec_request` takes the command, runs it through the same fake interpreter (splitting `cd ~; uname -a && whoami` into parts) and returns the output with an exit code.
- `shell_commands.json` has a new field, `canal`, which is `shell` or `exec`, so detection rules can tell them apart.
- Splitting on `;` and `&&` is an approximation. It does not understand quotes or pipes.

I tested it locally with paramiko clients (a simple command, a chained one, an unknown command, an `authorized_keys` write, a `wget`, an interactive shell and a connection that never opens a channel) and in production with a connection from my own phone. Data from before 26 October (about 21:35 UTC) has no `exec` commands, so any before and after comparison has to start there.

### Closing the realism gaps found in the logs

On 27 October the logs showed three places where the fake shell gave itself away, so I fixed them:

- **`uname` with options.** 56 of 56 `exec` commands were `uname -s -v -n -r -m` and the honeypot answered `command not found`, which a real Linux never does. `uname` now understands the real flags (`-s -n -r -v -m -p -i -o -a` and the long forms), prints them in the same order as the real tool and rejects invalid ones the way it does.
- **`sh -c` and `bash -c`.** The inner command is now executed, so a `wget` hidden inside `sh -c "..."` is detected like a loose one. Nesting is capped at 3 levels.
- **Chained commands in the interactive shell.** `echo; echo x` or `ls; exit` used to be read as one word. The splitting that only `exec` had (`;`, `&&`, `||`, newlines, respecting quotes) now lives in `get_response`, so both channels behave the same way.

A bug that had been logging false alerts also went away: `cat /etc/passwd` matched the substring `passwd` and was treated as an attempt to change a password. Now `passwd` only counts as a command.

Known limits: pipes, redirections, `$( )`, loops and `if`/`case` are still not interpreted. The next section covers what the shell can now compute.

### Passing the shell capability check

Some bots do not ask whether a file exists. They send a small script and check that the shell actually computes: `printf` with a random marker, `$((a*b+c))`, `$$`, `set --` with positional parameters and a function. Until now the fake shell answered `command not found` to all of it, which a real shell never does. By 29 October the logs held 245 commands of this kind.

`shell_interp.py` is a small interpreter for exactly that subset: `printf` (formats, width, and reuse of the format when there are more arguments), `echo`, integer arithmetic with 64-bit wraparound, variables, `$$ $# $? $1...`, `set --`, `shift`, functions, and `;`, `&&`, `||`. Output is now exact, including the trailing newline: `printf abc` returns `abc` without a newline, as on Linux.

Why it is safe to run attacker text through it:

- Attacker text never reaches `eval`, `exec`, a subprocess or a real shell. It is read character by character and reduced to data.
- Arithmetic is checked against a whitelist of characters and then evaluated by walking the syntax tree with a whitelist of operators. Expression length, exponents and shifts are capped.
- Everything is bounded: 20 commands per list, 200 steps per order, 8 levels of function calls, 3 levels of `sh -c` and 20,000 characters of `printf` output.
- Each `sh -c` behaves like its own process: it gets its own PID and does not see the caller's functions or parameters.

Still missing: `test` and `[`, and the dash error messages. A real Ubuntu runs `sh -c` with dash, which says `sh: 1: foobar: not found`, while this shell answers in bash style. I have not changed that yet.

### Ignoring my own traffic

Testing from home put my own connections in the logs. The `HONEYPOT_IGNORE_IPS` variable takes a comma-separated list of IPs or CIDR ranges that every collector skips (SSH, HTTP, FTP, shell commands and malware capture). Put it in a `.env` file, which is gitignored. Use exact IPs: an ISP range such as a /24 also hides other customers of the same provider.

This only helps going forward. Events that were already logged have to be cleaned by hand.

### Geolocation of older events

HTTP and FTP events used to be stored without coordinates, so they did not appear on the map. `backfill_geo.py` fills country, city, ISP and coordinates for the old events:

```bash
sudo docker compose exec honeypot python backfill_geo.py --dry-run
sudo docker compose exec honeypot python backfill_geo.py
```

It makes one lookup per unique IP and waits between requests to stay under the free rate limit of ip-api.com (about 45 per minute). In my last run it updated 183 events from 89 IPs, with none left without data.

### Daily summary for analysis

`resumen_diario.py` turns the five JSON logs into a short text report of what happened in a time window. It runs on the server next to the logs and needs nothing beyond Python:

```bash
cd ~/honeypot-aws
python3 resumen_diario.py                  # last 24 hours
python3 resumen_diario.py --horas 72       # longer window
python3 resumen_diario.py --ip a3f9c1d2    # full timeline of one IP
python3 resumen_diario.py --ignorar 172.18.0.1
```

I use it for a daily routine: read the report, pick the one or two behaviors that stand out, write a hypothesis, and decide whether it is worth a Wazuh rule or needs more days of data. Each hypothesis is recorded with its evidence, so wrong ones stay visible too. The public log is [HYPOTHESES.md](HYPOTHESES.md) (in Spanish, with no IPs).

- **IPs are masked.** `203.0.113.7` appears as `203.0.x.x#a3f9c1d2`. The suffix is an HMAC-SHA256 of the full address with a secret salt (`RESUMEN_SALT`, or the file `~/.honeypot_resumen_salt`, created on the first run with mode 600 and kept out of git and the container), so the same IP is recognized from one day to the next and nobody without the salt can recover it. A plain hash would not be enough: with the first two octets visible only 65,536 addresses are possible, and trying all of them takes milliseconds. If the salt is lost the suffixes change. `--sin-mascara` shows the IPs whole.
- **It remembers.** The report separates new IPs from ones seen in the previous 30 days (`--historial-dias`), and lists the recent history of the recurring ones.
- **Flags are triage, not conclusions.** An IP gets flags such as `recurrente`, `ritmo lento` (several days, at most two attempts per day), `autentico y se fue` or `ejecuto comandos`. They only decide what to read first.
- **Attacker text is untrusted.** Usernames, passwords, commands and URLs are stripped of control characters and shortened, so a hostile string cannot pass as a line of its own in the report.
- **Probe commands are grouped.** The bots' shell checks change only in a random hash and a few numbers, so they collapse into one line.

It does not touch the honeypot or the container, so running it does not affect the measurement window.

### Project structure

```
honeypot-aws/
├── honeypot.py          # Entry point, starts all services
├── fake_shell.py        # Fake interactive SSH shell and authentication
├── shell_interp.py      # Mini interpreter: printf, arithmetic, $$, functions (no eval)
├── resumen_diario.py    # Daily summary of the logs, with masked IPs (standard library only)
├── weak_passwords.py    # Weak and default credentials that get accepted
├── http_honeypot.py     # HTTP honeypot server
├── ftp_honeypot.py      # FTP honeypot server
├── logger.py            # Central logging and geolocation
├── connection_logger.py # One log line per SSH connection and how it ended
├── shell_logger.py      # Logs executed commands
├── stats.py             # Console stats
├── mapa.py              # Static map generator (folium)
├── dashboard.py         # Flask and WebSockets dashboard
├── dashboard_auth.py    # Dashboard login: one password, session cookie, websocket included
├── ml_classifier.py     # ML attacker classification
├── fingerprint.py       # Tool identification
├── malware_capture.py   # Malware capture and analysis
├── threat_intel.py      # AbuseIPDB and Shodan lookups
├── alertas.py           # Email alert system
├── backfill_geo.py      # Fills coordinates for old HTTP/FTP events
├── config.py            # Central config
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── requirements-dev.txt # Test dependencies (pytest)
├── pytest.ini
├── tests/               # Fake shell tests, an end-to-end SSH test and a fuzz test
└── logs/                # Generated at runtime, not in the repo
    ├── attempts.json
    ├── http_attempts.json
    ├── ftp_attempts.json
    ├── shell_commands.json
    ├── ssh_connections.json
    ├── fingerprints.json
    ├── ml_classifications.json
    ├── malware_captures.json
    ├── threat_intel.json
    ├── ssh_host_rsa_key
    └── malware_samples/
```

### Tech stack

| Category | Technology |
|---|---|
| Language | Python 3.11 |
| SSH protocol | paramiko |
| Web framework | Flask and Flask-SocketIO |
| Machine learning | scikit-learn (Random Forest) |
| Maps | Leaflet.js with OpenStreetMap tiles, folium for the static map |
| Visualization | Chart.js |
| Detection | Wazuh 4.14.8 (agent and manager) |
| Infrastructure | AWS EC2, Docker and Docker Compose (first run on Azure) |

### External services it depends on

| Service | Used for | If it is down or limited |
|---|---|---|
| ip-api.com | Geolocation of every IP (free tier, about 45 requests per minute) | Events are logged without coordinates. `backfill_geo.py` can fill them later |
| OpenStreetMap tile servers | Map background | The map shows markers on an empty background |
| AbuseIPDB and Shodan | IP reputation (optional, needs API keys) | Disabled unless `THREAT_INTEL_ENABLED=true` |
| VirusTotal | Hash check of captured files (optional, needs an API key) | The hash is stored with no verdict |

The dashboard also loads Leaflet, Chart.js and Socket.IO in the browser.

### Tests

```bash
pip install -r requirements-dev.txt
pytest
```

The suite covers the fake shell and its interpreter, the login rules and full SSH sessions. It needs no network and writes nothing to disk, because `tests/conftest.py` replaces the loggers and the malware downloader with test doubles before importing `fake_shell`.

- **Fake shell (`tests/test_fake_shell.py`).** Each test pins one answer a real Linux box would give: `uname` with any option combination, exit codes (`127` for an unknown command), `cd`/`pwd`/prompt consistency, chained commands with `;`, `&&` and `||` without splitting inside quotes, `sh -c`, and the exec channel. Several cases come from commands that actually reached the honeypot, such as `uname -s -v -n -r -m` and `/ip cloud print`.
- **A regression I had already hit.** `cat /etc/passwd` must not be logged as a system modification attempt. The test exists because the word `passwd` once triggered that alert.
- **Login rules.** Weak passwords get in on the first try, strong ones on the third attempt from the same IP, and old failures expire after ten minutes.
- **End to end (`tests/test_ssh_integration.py`).** A real paramiko client connects to the fake server over an in-memory socket pair, authenticates, runs an exec command and opens an interactive shell. Its main job is to catch breakage when paramiko is upgraded.
- **The bot's shell check, verbatim.** `tests/fixtures/examen_shell.txt` holds the seven commands exactly as they were logged (only the random hash is replaced). They run in-process and through a real SSH client, one connection per command, as the bots do.
- **Arithmetic and safety.** Operator precedence, C-style division and modulo, 64-bit wraparound, and a set of inputs that must be rejected: Python code inside `$(( ))`, `9**9**9`, huge shifts and deeply nested parentheses.
- **Fuzzing.** `tests/test_fuzz_shell.py` throws random mixes of shell metacharacters at the shell with fixed seeds. The rule is simple: nothing raises and nothing takes more than half a second. The first run found a crash (`$VAR` on an unset variable left no command to run), now fixed and covered.
- **Daily summary (`tests/test_resumen_diario.py`).** Masking that never shows the full address, hostile text flattened to one line, probe commands grouped, the slow-pace flag firing for one attempt per day and not for a fast burst, private and ignored IPs left out, and a run from the command line.
- **Dashboard login (`tests/test_dashboard_auth.py`).** The dashboard is locked without a password, pages redirect and the API answers 401 without a login, wrong and empty passwords never get a session, the lockout after five failures lifts with time, the cookie flags, and the websocket refused without a login, after logout and for a second browser, including the real Socket.IO handshake over HTTP.

### Local setup

Requirements: Python 3.9 or newer and pip.

```bash
git clone https://github.com/TinchoLay/ssh-honeypot.git
cd ssh-honeypot

python -m venv venv

# Windows:
venv\Scripts\activate
# Linux and Mac:
source venv/bin/activate

pip install -r requirements.txt
python honeypot.py
```

The dashboard runs at `http://localhost:5000`.

### Running it on a server

1. Create an Ubuntu VM (I used Azure first and EC2 now) and install Docker.
2. In the cloud firewall, open 2222, 8080 and 2121. Keep the dashboard port closed and use an SSH tunnel for it. Open 22 only if you use the port forward above.
3. Clone the repo, create a `.env` file if you need one and start it:

```bash
git clone https://github.com/TinchoLay/ssh-honeypot.git
cd ssh-honeypot
docker compose up -d --build
```

When you rebuild, check that the build output does not say `CACHED` for the steps you changed, or the old code keeps running.

### Container hardening

The honeypot is meant to receive hostile traffic, so the container gets only what it needs:

- Runs as an unprivileged user (UID 10001), not as root.
- `read_only: true` with a `tmpfs` on `/tmp`. The only writable place is the `logs/` volume, which is where every log, the host key and the ML model are written.
- `cap_drop: ALL`. All its ports are above 1024, so it needs no Linux capabilities.
- `no-new-privileges`, a process limit (`pids_limit`) and a memory limit.

The `logs/` folder on the host must belong to UID 10001, or the container cannot write to it. If you are migrating a deployment that used to run as root:

```bash
sudo chown -R 10001:10001 logs
```

### Why paramiko stays on 4.0.0

paramiko 4.0.0 is affected by CVE-2026-44405 (SHA-1 allowed in RSA signatures, CVSS 3.4, no known public exploitation). Version 5 removes SHA-1 entirely, and I tested what that changes here: an OpenSSH client that offers only `diffie-hellman-group14-sha1` negotiates with 4.0.0 and is rejected by 5.1.0 ("no matching key exchange method found"). Modern clients notice nothing.

For a normal SSH server that is the right trade. For a honeypot it is the opposite: it protects no real data, and the old SHA-1-only scanners and IoT botnets are exactly the traffic I want to observe. So I am staying on 4.0.0 for the measurement window, with this written down, and I will compare against 5.x later. `pip-audit` will flag the CVE, and the justification above is the accepted exception.

The test suite passes on both versions, so the upgrade itself is a one-line change in `requirements.txt` (5.x also needs `invoke` 3.0.3).

### Continuous integration and dependency audit

`.github/workflows/ci.yml` runs on every push and pull request, and every Monday:

- `pytest` on Python 3.11, the version in the Dockerfile.
- `pip-audit` on `requirements.txt`. Every dependency is pinned, so the audit checks exactly what the container installs. The only accepted exception is CVE-2026-44405 (see above). Any other advisory fails the build.

The weekly run matters because new advisories appear without any change in the code.

**What the first audit found (2026-10-30).** Besides paramiko, eight pinned packages had known advisories: certifi, cryptography, filelock, idna, python-engineio, python-socketio, urllib3 and Werkzeug. Two groups matter most here. idna and urllib3 sit on the path of `malware_capture.py`, which fetches URLs chosen by the attacker (the SSRF check is separate and unchanged). python-engineio and python-socketio serve the dashboard websocket. I moved all eight to fixed versions in one step, including `cryptography` from 46.0.6 to 50.0.2, which is a big jump. Evidence: the whole test suite passes on the new versions (including a real paramiko session) and `pip-audit` reports only the accepted paramiko exception. I also compared the key exchange packet the server sends (KEXINIT: key exchange, host key, cipher and MAC lists) under `cryptography` 46.0.6 and 50.0.2, and the lists are identical, so what an attacker sees in the SSH handshake does not change. Not covered: I have not run the rebuilt container yet, so the first deploy gets a close look at the logs.

Limits: `pip-audit` only knows published advisories, and it says nothing about the honeypot's own code.

### Dashboard login

The dashboard asks for a password. It was already reachable only through an SSH tunnel, so this is a second layer: someone who reaches the port (a shared tunnel, another user on the server, a web page pointing at `localhost:5000`) still needs the password.

- **Where the password lives.** `DASHBOARD_PASSWORD` in the `.env` file next to `docker-compose.yml`, outside git like the other secrets. To create one on the server without printing it: `echo "DASHBOARD_PASSWORD=$(openssl rand -base64 18 | tr -d '/+=')" >> .env`, then `chmod 600 .env`.
- **Locked, not open.** With no password set, every route answers 503 instead of showing data. `DASHBOARD_AUTH=off` turns the login off on purpose, for local development only.
- **The websocket is covered.** Socket.IO serves `/socket.io/` before Flask sees the request, so a normal login check misses it. The `connect` handler checks the session and refuses without a login. The tests walk the protocol's real HTTP handshake, not only the test client, and breaking that check makes six of them fail.
- **Cookie and brute force.** Signed cookie, `HttpOnly`, `SameSite=Strict`, 12-hour session. Five wrong passwords within five minutes lock the login for one minute.

Two things I fixed on the way. The key that signs the cookies was a fixed string in the code, and the websocket accepted any origin (`cors_allowed_origins="*"`). Now the key comes from `DASHBOARD_SECRET_KEY` or is random at each start, and the websocket only accepts the same origin as the page.

Limits: one shared password, no second factor, and the attempt limit is global because behind the tunnel everyone arrives as the same address. A client without a login can still open an Engine.IO session, but the server refuses the namespace and sends it nothing.

### Environment variables

```bash
GEO_ENABLED=true              # IP geolocation (default: true)
HONEYPOT_IGNORE_IPS=          # Comma-separated IPs or CIDR ranges to skip
EMAIL_ENABLED=false           # Email alerts (default: false)
EMAIL_SENDER=your@gmail.com
EMAIL_PASSWORD=app_password
EMAIL_RECEIVER=destination@gmail.com
ALERT_THRESHOLD=5             # Attempts before alerting (default: 5)
ALERT_WINDOW=60               # Time window in seconds (default: 60)
THREAT_INTEL_ENABLED=false    # AbuseIPDB and Shodan lookups (default: false)
ABUSEIPDB_KEY=your_api_key
SHODAN_KEY=your_api_key
VIRUSTOTAL_KEY=your_api_key
DASHBOARD_PASSWORD=           # Dashboard login. Empty = dashboard locked (503)
DASHBOARD_SECRET_KEY=         # Optional: signs the session cookies (random at each start if empty)
DASHBOARD_AUTH=               # off = no login, for local development only
```

### What real internet traffic looks like

- The first attempts arrive within minutes. I did not advertise the server anywhere.
- SSH on 2222 was quiet. The few attempts used default usernames and weak passwords: `root`, `admin` and `user` with `123456`, `password`, `admin123`, `qwerty` and `admin`.
- HTTP traffic comes mostly from scanners looking for admin panels (`/login`, `/admin`, `/wp-admin`), WordPress, Jenkins and exposed config files. There were also GPON router exploit attempts and open proxy probes.
- The most active IPs trace back to Tor exit nodes, VPS ranges and Chinese IP blocks.
- The bots are very regular, with milliseconds between attempts.

On 26 October, after a week with port 22 open, the dashboard showed 2,899 events from 631 unique IPs: 2,058 SSH login attempts, 838 HTTP requests and a few FTP. Before port 22 it was 247 events from 111 IPs.

The raw total is misleading. Four addresses from a single /24 made 1,716 of the SSH attempts (83%). That block most likely explains the spike of about 900 to 950 events a day on 20 and 21 October, though I have not checked the timestamps. It also explains why the day-of-week chart puts Tuesday and Wednesday far above the rest, and probably why France leads the country chart with 1,781 events. None of that shows that attackers prefer Tuesdays or France. It is one campaign. Country is where the IP is registered, usually a hosting provider, not where the attacker sits.

Outside the spike, activity settled at roughly 80 to 190 events a day, up from 60 to 70 before port 22. I think port 22 explains the increase, but I have not split the counts by port to confirm it.

### What I learned building this

- How SSH works inside: key negotiation, authentication and channels.
- Raw TCP servers with Python's `socket` module, and paramiko to control SSH sessions.
- Flask with WebSockets to keep a dashboard updating live, and why every event reloading everything stops scaling.
- Training and wiring a scikit-learn model with real captured data.
- Consuming REST APIs and living with their rate limits (ip-api, AbuseIPDB, Shodan, VirusTotal).
- Cloud networking and firewall rules, and how Docker's port publishing hides the source IP.
- Concurrency with `threading`.
- The unglamorous production side: running in the background, not losing logs, restarting after a crash, and cleaning my own traffic out of the data.
- Realism is an arms race. Every detail that is wrong is something a scanner can fingerprint.
- Check what the honeypot cannot see. 802 connections got in and left no commands, and the reason was a missing handler in my code, not quiet attackers.
- One campaign can distort every chart. Look at the top IPs before reading a trend into totals by day or country.
- A rule or a feature that passes a local test is not in production until it is deployed and a real event goes through it.

### Ethics and legal notes

This project exists to learn cybersecurity. The honeypot only captures data from people trying to get into a server that is mine, without permission. Do not use it against systems that are not yours or for anything malicious.

### Author

Martín, IT support and cybersecurity, working toward a SOC L1 role.

[GitHub](https://github.com/TinchoLay) · [LinkedIn](https://www.linkedin.com/in/martin-chancalay-902b543a8)

---

## Español

Un honeypot es un servidor señuelo. Parece real y acepta conexiones, pero no tiene nada de valor adentro. Su único trabajo es atraer atacantes y registrar lo que hacen. Este proyecto simula tres servicios (SSH, HTTP y FTP). Primero corrió en una VM de Azure y ahora corre en Docker sobre AWS EC2, expuesto a internet y recibiendo tráfico de atacantes reales. Un agente de Wazuh manda sus logs a un manager de Wazuh, donde unas [reglas de detección propias](https://github.com/TinchoLay/wazuh-detection-pack/tree/main/honeypot) los convierten en alertas.

Es un proyecto para aprender. El honeypot solo captura tráfico dirigido a un servidor que es mío.

### Qué hace

Alguien se conecta a uno de los puertos abiertos, pensando que encontró un servidor de verdad. El honeypot lo deja entrar, guarda el usuario y la contraseña que probó y ubica de dónde viene la IP. A partir de ahí:

- Un modelo de machine learning intenta adivinar qué tipo de atacante es: un bot que prueba miles de combinaciones, o alguien más lento que apunta a este servidor.
- Lee el banner que manda el cliente SSH al conectarse, que muchas veces delata la herramienta (Hydra, Metasploit, un script casero).
- Si el atacante intenta `wget` o `curl`, el honeypot lo deja creer que funcionó y descarga el archivo real en segundo plano para analizarlo.
- Cruza la IP contra AbuseIPDB y Shodan.
- Todo aparece en vivo en un dashboard web.

### Los tres servicios falsos

- **SSH (2222, y 22 mediante un reenvío de puerto):** el más elaborado. Abre una shell interactiva falsa que imita Ubuntu 22.04. El atacante puede tipear `ls`, `cd`, `whoami` o `cat /etc/passwd` y recibe respuestas creíbles. Todo lo que escribe queda registrado. También responde comandos enviados de una sola vez (`ssh host "uname -a"`), que las herramientas automáticas suelen usar en lugar de abrir una sesión.
- **HTTP (8080):** un panel de administración falso con la pinta de un router TP-Link. Atrapa scanners que buscan paneles mal protegidos. Guarda el método, la ruta, los headers y el cuerpo del POST.
- **FTP (2121):** acepta la conexión y rechaza cualquier credencial. Muestra qué usuarios y contraseñas se prueban ahí.

### Hacerlo más difícil de detectar

Un honeypot fácil de reconocer solo junta tráfico de los bots más vagos. Hice estos cambios después de pensar cómo lo identificaría un scanner:

- **Clave de host persistente.** Antes generaba una clave nueva en cada arranque, algo que un scanner que vuelve nota enseguida. Ahora la clave vive en `logs/` y sobrevive a los reinicios.
- **Banner completo.** La cadena de versión de SSH coincide con una build real de OpenSSH de Ubuntu 22.04.
- **Autenticación creíble.** El login se acepta si la contraseña está en una lista de credenciales débiles y de fábrica (`weak_passwords.py`, 69 entradas de listas de contraseñas comunes y defaults de IoT), o al tercer intento desde la misma IP dentro de 10 minutos. Un servidor que acepta todo al primer intento parece falso.
- **Una shell que recuerda dónde estás.** `cd`, `pwd` y `ls` funcionan sobre un filesystem falso chico. Un home recién creado está vacío, `ls -la` muestra los dotfiles, `/` lista los directorios de siempre y `/root` da "Permission denied" a los usuarios comunes. El prompt sigue el directorio actual.
- **Salida según el usuario.** `whoami`, `id` y la línea "Last login" coinciden con el usuario que entró.
- **Mensajes de error como los de bash.** `echo "..." >> archivo` no imprime nada, y ejecutar una ruta que no existe (`./x.sh`) responde "No such file or directory" en vez de "command not found".

Son medidas propias contra el fingerprinting. No las probé contra un scanner hecho para detectar honeypots, así que no afirmo que sea indetectable.

### Cómo clasifica a los atacantes

Un Random Forest entrenado con los datos que captura el honeypot, que se reentrena solo cada 100 intentos. Los separa en cuatro grupos:

- `bot_fuerza_bruta`: scripts automáticos que prueban credenciales a toda velocidad
- `scanner`: barre puertos y servicios sin intentar entrar en algo puntual
- `script_kiddie`: usa herramientas conocidas como Hydra sin mucha estrategia
- `atacante_dirigido`: más lento y más humano, parece apuntar a este servidor

### Análisis de malware

Cuando alguien baja un archivo, el honeypot lo descarga en segundo plano, calcula su MD5 y SHA256 y consulta el hash en VirusTotal. El resultado queda guardado con la cantidad de motores que lo marcaron. La regla 100320 de Wazuh salta cuando al menos un motor lo hace.

### Dashboard

Un panel con Flask y WebSockets que se actualiza cuando entra un ataque nuevo. Tiene tres pestañas:

- **Stats:** totales por protocolo, usuarios y contraseñas más probados, países de origen y un log en vivo.
- **Análisis:** gráficos de ataques por hora del día y día de la semana, y desde dónde.
- **Mapa:** todos los eventos SSH, HTTP y FTP en un mapa mundial, con dos filtros que se combinan. Tipo: todos, SSH, HTTP o FTP. Período: última hora, 24 horas, 3 días, semana, mes o desde el inicio. Así, "FTP de las últimas 24 horas" son un clic en cada filtro.

El mapa usa tiles de OpenStreetMap. Al principio usé los de CARTO y empezaron a pedir una API key, lo que convirtió el mapa en un mensaje de error. Las actualizaciones se agrupan con un retraso de 1,5 segundos, porque con el puerto 22 abierto cada evento recargaba los logs y reenviaba todo, y el costo crecía con cada conexión.

El dashboard escucha solo en `127.0.0.1:5000`. No está expuesto a internet, así que se accede por un túnel SSH.

![Pestaña Stats, capturada con 51 eventos de 21 IPs únicas](assets/01-dashboard-stats.png)

![Pestaña Análisis: ataques por hora del día, día de la semana, países y línea de tiempo](assets/02-dashboard-analysis.png)

![Pestaña Mapa: origen de los ataques en un mapa mundial](assets/03-attack-map.png)

![El honeypot arrancando: SSH en 2222, HTTP en 8080, FTP en 2121, dashboard en 5000](assets/04-startup-terminal.png)

![Requests HTTP en el log en vivo](assets/05-http-requests.png)

### Detección con Wazuh

El honeypot escribe una línea JSON por evento y un agente de Wazuh en la misma máquina la manda a un manager. Las reglas (fuerza bruta SSH rápida y lenta, cómo terminó cada conexión SSH, comandos que escribe el atacante, intentos de descarga, hallazgos de VirusTotal, rutas de exploit de GPON, pruebas de proxy abierto, objetivos de scanners, FTP anónimo) están en el repositorio [wazuh-detection-pack](https://github.com/TinchoLay/wazuh-detection-pack/tree/main/honeypot), con las pruebas que hice y lo que no pude verificar.

### Usar el puerto 22

Los scanners prueban primero el puerto 22, así que un honeypot que solo escucha en el 2222 ve poco. El `sshd` de administración de esta máquina queda en el 22, solo con clave. Para atrapar el tráfico reenvío el puerto 22 al contenedor con una regla DNAT en la tabla `nat`. La regla saltea la red desde la que administro la máquina, así el `sshd` real sigue accesible para mí y para nadie más:

```bash
CIP=$(sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ssh-honeypot)
sudo iptables -t nat -A PREROUTING ! -s ADMIN_NET -p tcp --dport 22 -j DNAT --to-destination $CIP:2222
```

Reemplazá `ADMIN_NET` por la IP o el rango desde el que te conectás (por ejemplo `203.0.113.0/24`).

Tres detalles me hicieron perder tiempo:

- **Sin la exclusión te dejás afuera.** Un DNAT sobre todos los orígenes manda también tu propia administración al honeypot. Con la exclusión, si tu IP sale de ese rango te quedás sin acceso al `sshd` de administración. Mi forma de volver es reiniciar (la regla no persiste) o usar EC2 Instance Connect.

- **Por qué DNAT y no una redirección al 2222.** El puerto 2222 lo publica Docker a través de `docker-proxy`. Si redirigís a ese puerto, todos los atacantes llegan al contenedor con la dirección del bridge y se pierde la IP de origen real. Eso rompe la geolocalización y toda detección que cuente intentos por IP. DNAT directo a la dirección del contenedor conserva el origen.
- **La regla no sobrevive a un reinicio y la dirección del contenedor puede cambiar después de reconstruirlo.** Después de `docker compose up --build`, borrá la regla vieja (`iptables -t nat -D PREROUTING <n>`) y agregala de nuevo con la dirección nueva. Después de un reinicio vuelve a responder el `sshd` real en el 22, que es la forma segura de fallar.

El security group tiene que permitir el puerto 22 de entrada, y entonces cualquiera en internet llega a ese puerto. Hacelo solo en una máquina pensada para esto.

Para probar el honeypot en el puerto 22, conectate desde fuera del rango excluido (yo uso datos del celular). Desde adentro llegás al `sshd` real. Conectarse a la misma IP desde los dos lados también dispara el aviso "host key changed", porque los dos servicios tienen claves de host distintas.

### Cada conexión SSH, y comandos enviados sin shell

El puerto 22 trae muchas conexiones que nunca prueban una contraseña, así que contar intentos de login esconde casi todo lo que pasa. `connection_logger.py` escribe una línea por conexión SSH en `logs/ssh_connections.json`, con cómo terminó:

| Resultado | Qué significa |
|---|---|
| `sin_banner` | Se conectó y cerró sin mandar un banner SSH. Típico de scanners de puertos |
| `error_protocolo` | Mandó un banner, pero la negociación SSH falló |
| `sin_autenticacion` | Negoció SSH y nunca intentó loguearse |
| `login_fallido` | Intentó loguearse y fue rechazado |
| `autenticado_sin_shell` | Entró y nunca pidió una shell ni un comando |
| `exec` | Entró y mandó un solo comando (`ssh host "uname -a"`) |
| `shell` | Entró y abrió una shell interactiva |

Cada línea también tiene el banner del cliente, la duración, la cantidad de intentos de login y, en `exec`, el comando en `detalle`. Las IPs de `HONEYPOT_IGNORE_IPS` se saltean. Los logs de Docker rotan (10 MB, 3 archivos) para que el ruido de los scanners no llene el disco, y los tracebacks de paramiko por conexiones cortadas se silenciaron porque el evento ya queda registrado acá.

La primera semana con el puerto 22 abierto (del 19 al 26 de octubre, 2.873 conexiones) terminó así: 1.250 `login_fallido`, 802 `autenticado_sin_shell`, 669 `sin_banner`, 78 `error_protocolo`, 71 `sin_autenticacion` y solo 3 `shell`. Las tres líneas `autenticado_sin_shell` que miré venían de clientes `SSH-2.0-Go` y hicieron un solo intento de login.

Ese número me hizo leer mi propio código. El honeypot solo reaccionaba a pedidos de shell interactiva. Un cliente que manda un comando directo era rechazado por el comportamiento por defecto de paramiko, así que su comando nunca se registraba. Todavía no sé cuántas de esas 802 conexiones mandaron uno. El 26 de octubre agregué el soporte:

- `check_channel_exec_request` toma el comando, lo ejecuta con el mismo intérprete falso (separando `cd ~; uname -a && whoami` en partes) y devuelve la salida con un código de salida.
- `shell_commands.json` tiene un campo nuevo, `canal`, que vale `shell` o `exec`, para que las reglas de detección los distingan.
- Separar por `;` y `&&` es una aproximación. No entiende comillas ni pipes.

Lo probé en local con clientes de paramiko (un comando simple, uno encadenado, uno inexistente, una escritura en `authorized_keys`, un `wget`, una shell interactiva y una conexión que nunca abre un canal) y en producción con una conexión desde mi propio celular. Los datos anteriores al 26 de octubre (alrededor de las 21:35 UTC) no tienen comandos `exec`, así que cualquier comparación de antes y después tiene que arrancar desde ahí.

### Cerrar los huecos de realismo que mostraron los logs

El 27 de octubre los logs mostraron tres lugares donde la shell falsa se delataba, así que los arreglé:

- **`uname` con opciones.** 56 de 56 comandos `exec` eran `uname -s -v -n -r -m` y el honeypot respondía `command not found`, algo que un Linux real nunca hace. Ahora `uname` entiende las opciones reales (`-s -n -r -v -m -p -i -o -a` y las formas largas), las imprime en el mismo orden que la herramienta real y rechaza las inválidas como lo hace ella.
- **`sh -c` y `bash -c`.** Ahora se ejecuta el comando de adentro, así que un `wget` escondido en `sh -c "..."` se detecta igual que uno suelto. El anidado se limita a 3 niveles.
- **Comandos encadenados en la shell interactiva.** `echo; echo x` o `ls; exit` se leían como una sola palabra. La separación que solo tenía `exec` (`;`, `&&`, `||`, saltos de línea, respetando comillas) ahora vive en `get_response`, así que los dos canales se comportan igual.

También desapareció un bug que generaba falsas alertas: `cat /etc/passwd` coincidía con la cadena `passwd` y se trataba como un intento de cambiar una contraseña. Ahora `passwd` solo cuenta como comando.

Límites conocidos: pipes, redirecciones, `$( )`, bucles y `if`/`case` todavía no se interpretan. La sección siguiente cuenta lo que la shell ya sabe calcular.

### Pasar la verificación de capacidades de la shell

Algunos bots no preguntan si existe un archivo. Mandan un script chico y comprueban que la shell realmente calcule: `printf` con un marcador al azar, `$((a*b+c))`, `$$`, `set --` con parámetros posicionales y una función. Hasta ahora la shell falsa respondía `command not found` a todo eso, algo que una shell real nunca hace. Al 29 de octubre los logs tenían 245 comandos de este tipo.

`shell_interp.py` es un intérprete chico para exactamente ese subconjunto: `printf` (formatos, ancho y reutilización del formato cuando sobran argumentos), `echo`, aritmética entera con desborde a 64 bits, variables, `$$ $# $? $1...`, `set --`, `shift`, funciones, y `;`, `&&`, `||`. La salida ahora es exacta, con su salto de línea final: `printf abc` devuelve `abc` sin salto, como en Linux.

Por qué es seguro pasarle texto de un atacante:

- El texto del atacante nunca llega a `eval`, `exec`, un subproceso ni una shell real. Se lo lee carácter por carácter y se lo reduce a datos.
- La aritmética pasa primero por una lista blanca de caracteres y después se evalúa recorriendo el árbol de sintaxis con una lista blanca de operadores. El largo de la expresión, los exponentes y los desplazamientos tienen tope.
- Todo está acotado: 20 comandos por lista, 200 pasos por orden, 8 niveles de funciones, 3 niveles de `sh -c` y 20.000 caracteres de salida de `printf`.
- Cada `sh -c` se comporta como un proceso propio: tiene su PID y no ve las funciones ni los parámetros de quien lo llamó.

Todavía falta: `test` y `[`, y los mensajes de error de dash. Un Ubuntu real ejecuta `sh -c` con dash, que dice `sh: 1: foobar: not found`, mientras que esta shell responde al estilo de bash. Eso todavía no lo cambié.

### Ignorar mi propio tráfico

Probar desde casa metió mis propias conexiones en los logs. La variable `HONEYPOT_IGNORE_IPS` recibe una lista separada por comas de IPs o rangos CIDR que todos los colectores saltean (SSH, HTTP, FTP, comandos de la shell y captura de malware). Va en un archivo `.env`, que está en el gitignore. Usá IPs exactas: un rango del proveedor como un /24 también oculta a otros clientes del mismo proveedor.

Solo sirve hacia adelante. Los eventos que ya se registraron hay que limpiarlos a mano.

### Geolocalización de eventos viejos

Los eventos HTTP y FTP se guardaban sin coordenadas, así que no aparecían en el mapa. `backfill_geo.py` completa país, ciudad, ISP y coordenadas de los eventos viejos:

```bash
sudo docker compose exec honeypot python backfill_geo.py --dry-run
sudo docker compose exec honeypot python backfill_geo.py
```

Hace una consulta por IP única y espera entre pedidos para quedar bajo el límite gratuito de ip-api.com (unas 45 por minuto). En mi última corrida actualizó 183 eventos de 89 IPs, sin ninguna sin dato.

### Resumen diario para el análisis

`resumen_diario.py` convierte los cinco logs JSON en un informe de texto corto con lo que pasó en una ventana de tiempo. Corre en el servidor, junto a los logs, y no necesita nada más que Python:

```bash
cd ~/honeypot-aws
python3 resumen_diario.py                  # últimas 24 horas
python3 resumen_diario.py --horas 72       # ventana más larga
python3 resumen_diario.py --ip a3f9c1d2    # línea de tiempo completa de una IP
python3 resumen_diario.py --ignorar 172.18.0.1
```

Lo uso en una rutina diaria: leo el informe, elijo uno o dos comportamientos que se destacan, escribo una hipótesis y decido si vale una regla de Wazuh o si hacen falta más días de datos. Cada hipótesis queda registrada con su evidencia, así que las equivocadas también quedan a la vista. El registro público es [HYPOTHESES.md](HYPOTHESES.md) (en español, sin IPs).

- **Las IPs salen enmascaradas.** `203.0.113.7` aparece como `203.0.x.x#a3f9c1d2`. El sufijo es un HMAC-SHA256 de la dirección completa con una sal secreta (`RESUMEN_SALT`, o el archivo `~/.honeypot_resumen_salt`, que se crea en la primera corrida con permisos 600 y queda fuera de git y del contenedor), así la misma IP se reconoce de un día al otro y nadie sin la sal puede recuperarla. Un hash simple no alcanzaría: con los dos primeros octetos a la vista solo hay 65.536 direcciones posibles y probarlas todas toma milisegundos. Si se pierde la sal, los sufijos cambian. `--sin-mascara` muestra las IPs enteras.
- **Tiene memoria.** El informe separa las IPs nuevas de las vistas en los 30 días anteriores (`--historial-dias`) y lista el historial reciente de las recurrentes.
- **Las banderas son para decidir qué mirar primero, no son conclusiones.** Una IP puede recibir `recurrente`, `ritmo lento` (varios días, como mucho dos intentos por día), `autentico y se fue` o `ejecuto comandos`.
- **El texto del atacante no es de fiar.** Usuarios, contraseñas, comandos y URLs se limpian de caracteres de control y se acortan, para que una cadena hostil no pueda pasar por una línea propia del informe.
- **Las sondas se agrupan.** Las verificaciones de shell de los bots solo cambian en un hash al azar y unos números, así que se juntan en una sola línea.

No toca el honeypot ni el contenedor, así que correrlo no afecta la ventana de medición.

### Estructura del proyecto

```
honeypot-aws/
├── honeypot.py          # Punto de entrada, arranca todos los servicios
├── fake_shell.py        # Shell SSH interactiva falsa y autenticación
├── shell_interp.py      # Mini intérprete: printf, aritmética, $$, funciones (sin eval)
├── resumen_diario.py    # Resumen diario de los logs, con IPs enmascaradas (solo librería estándar)
├── weak_passwords.py    # Credenciales débiles y de fábrica que se aceptan
├── http_honeypot.py     # Servidor HTTP honeypot
├── ftp_honeypot.py      # Servidor FTP honeypot
├── logger.py            # Logging central y geolocalización
├── connection_logger.py # Una línea de log por conexión SSH y cómo terminó
├── shell_logger.py      # Registro de comandos ejecutados
├── stats.py             # Estadísticas en consola
├── mapa.py              # Generador de mapa estático (folium)
├── dashboard.py         # Dashboard Flask y WebSockets
├── dashboard_auth.py    # Login del dashboard: una clave, cookie de sesión, websocket incluido
├── ml_classifier.py     # Clasificación ML de atacantes
├── fingerprint.py       # Identificación de herramientas
├── malware_capture.py   # Captura y análisis de malware
├── threat_intel.py      # Consultas a AbuseIPDB y Shodan
├── alertas.py           # Sistema de alertas por email
├── backfill_geo.py      # Completa coordenadas de eventos HTTP/FTP viejos
├── config.py            # Configuración central
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── requirements-dev.txt # Dependencias de los tests (pytest)
├── pytest.ini
├── tests/               # Tests de la shell falsa, un test SSH de punta a punta y uno de fuzzing
└── logs/                # Se genera al correr, no está en el repo
    ├── attempts.json
    ├── http_attempts.json
    ├── ftp_attempts.json
    ├── shell_commands.json
    ├── ssh_connections.json
    ├── fingerprints.json
    ├── ml_classifications.json
    ├── malware_captures.json
    ├── threat_intel.json
    ├── ssh_host_rsa_key
    └── malware_samples/
```

### Stack técnico

| Categoría | Tecnología |
|---|---|
| Lenguaje | Python 3.11 |
| Protocolo SSH | paramiko |
| Web framework | Flask y Flask-SocketIO |
| Machine learning | scikit-learn (Random Forest) |
| Mapas | Leaflet.js con tiles de OpenStreetMap, folium para el mapa estático |
| Visualización | Chart.js |
| Detección | Wazuh 4.14.8 (agente y manager) |
| Infraestructura | AWS EC2, Docker y Docker Compose (primera corrida en Azure) |

### Servicios externos de los que depende

| Servicio | Para qué | Si se cae o se limita |
|---|---|---|
| ip-api.com | Geolocalización de cada IP (plan gratuito, unas 45 consultas por minuto) | Los eventos se guardan sin coordenadas. `backfill_geo.py` puede completarlas después |
| Servidores de tiles de OpenStreetMap | Fondo del mapa | El mapa muestra los marcadores sobre un fondo vacío |
| AbuseIPDB y Shodan | Reputación de IPs (opcional, necesita API keys) | Desactivado salvo que `THREAT_INTEL_ENABLED=true` |
| VirusTotal | Hash de los archivos capturados (opcional, necesita una API key) | El hash se guarda sin veredicto |

El dashboard además carga Leaflet, Chart.js y Socket.IO en el navegador.

### Tests

```bash
pip install -r requirements-dev.txt
pytest
```

La suite cubre la shell falsa y su intérprete, las reglas de login y sesiones SSH completas. No necesita red ni escribe en disco, porque `tests/conftest.py` reemplaza los loggers y el descargador de malware por dobles de prueba antes de importar `fake_shell`.

- **Shell falsa (`tests/test_fake_shell.py`).** Cada test fija una respuesta que daría un Linux real: `uname` con cualquier combinación de opciones, códigos de salida (`127` para un comando desconocido), coherencia entre `cd`, `pwd` y el prompt, comandos encadenados con `;`, `&&` y `||` sin cortar dentro de comillas, `sh -c` y el canal exec. Varios casos salen de comandos que llegaron de verdad al honeypot, como `uname -s -v -n -r -m` y `/ip cloud print`.
- **Una regresión que ya había tenido.** `cat /etc/passwd` no debe registrarse como intento de modificación del sistema. El test existe porque la palabra `passwd` llegó a disparar esa alerta.
- **Reglas de login.** Las contraseñas débiles entran al primer intento, las fuertes al tercero desde la misma IP, y los fallos viejos vencen a los diez minutos.
- **De punta a punta (`tests/test_ssh_integration.py`).** Un cliente paramiko real se conecta al servidor falso por un par de sockets en memoria, se autentica, ejecuta un comando por exec y abre una shell interactiva. Sirve sobre todo para detectar roturas cuando se actualiza paramiko.
- **La verificación del bot, tal cual.** `tests/fixtures/examen_shell.txt` guarda los siete comandos exactamente como se registraron (solo se reemplazó el hash al azar). Se ejecutan en el mismo proceso y con un cliente SSH real, una conexión por comando, como hacen los bots.
- **Aritmética y seguridad.** Precedencia de operadores, división y módulo al estilo C, desborde a 64 bits, y un conjunto de entradas que deben rechazarse: código Python dentro de `$(( ))`, `9**9**9`, desplazamientos enormes y paréntesis anidados en exceso.
- **Fuzzing.** `tests/test_fuzz_shell.py` le tira a la shell mezclas al azar de metacaracteres con semillas fijas. La regla es simple: nada lanza una excepción y nada tarda más de medio segundo. La primera corrida encontró un fallo (`$VAR` sobre una variable sin definir dejaba sin comando para ejecutar), ya corregido y cubierto.
- **Resumen diario (`tests/test_resumen_diario.py`).** Enmascarado que nunca muestra la dirección completa, texto hostil aplanado a una línea, sondas agrupadas, la bandera de ritmo lento que salta con un intento por día y no con una ráfaga rápida, IPs privadas e ignoradas fuera del informe, y una corrida desde la línea de comandos.
- **Login del dashboard (`tests/test_dashboard_auth.py`).** El dashboard queda bloqueado sin contraseña, las páginas redirigen y la API responde 401 sin login, las contraseñas incorrectas y vacías nunca dan sesión, el bloqueo tras cinco fallos se levanta con el tiempo, las banderas de la cookie, y el websocket rechazado sin login, después del logout y para un segundo navegador, incluido el handshake real de Socket.IO por HTTP.

### Instalación local

Requisitos: Python 3.9 o superior y pip.

```bash
git clone https://github.com/TinchoLay/ssh-honeypot.git
cd ssh-honeypot

python -m venv venv

# Windows:
venv\Scripts\activate
# Linux y Mac:
source venv/bin/activate

pip install -r requirements.txt
python honeypot.py
```

El dashboard queda en `http://localhost:5000`.

### Correrlo en un servidor

1. Crear una VM Ubuntu (usé Azure primero y ahora EC2) e instalar Docker.
2. En el firewall de la nube, abrir 2222, 8080 y 2121. Dejar cerrado el puerto del dashboard y usar un túnel SSH. Abrir el 22 solo si usás el reenvío de puerto de arriba.
3. Clonar el repo, crear un archivo `.env` si hace falta y levantarlo:

```bash
git clone https://github.com/TinchoLay/ssh-honeypot.git
cd ssh-honeypot
docker compose up -d --build
```

Cuando lo reconstruyas, fijate que la salida del build no diga `CACHED` en los pasos que cambiaste, o sigue corriendo el código viejo.

### Endurecimiento del contenedor

El honeypot está pensado para recibir tráfico hostil, así que el contenedor tiene solo lo que necesita:

- Corre con un usuario sin privilegios (UID 10001), no como root.
- `read_only: true` con un `tmpfs` en `/tmp`. El único lugar donde puede escribir es el volumen `logs/`, que es donde van todos los logs, la clave de host y el modelo de ML.
- `cap_drop: ALL`. Todos sus puertos son mayores a 1024, así que no necesita capacidades de Linux.
- `no-new-privileges`, un límite de procesos (`pids_limit`) y un límite de memoria.

La carpeta `logs/` del host tiene que pertenecer al UID 10001, o el contenedor no puede escribir en ella. Si se migra un despliegue que antes corría como root:

```bash
sudo chown -R 10001:10001 logs
```

### Por qué paramiko se queda en la 4.0.0

paramiko 4.0.0 está afectado por el CVE-2026-44405 (permite SHA-1 en firmas RSA, CVSS 3.4, sin explotación pública conocida). La versión 5 elimina SHA-1 por completo, y probé qué cambia acá: un cliente OpenSSH que ofrece solo `diffie-hellman-group14-sha1` negocia con la 4.0.0 y es rechazado por la 5.1.0 ("no matching key exchange method found"). Los clientes modernos no notan nada.

Para un servidor SSH normal, esa es la decisión correcta. Para un honeypot es al revés: no protege datos reales, y los escáneres viejos y las botnets de IoT que solo hablan SHA-1 son justo el tráfico que quiero observar. Por eso me quedo en la 4.0.0 durante la ventana de medición, con esto documentado, y más adelante comparo contra la 5.x. `pip-audit` va a marcar el CVE, y la justificación de arriba es la excepción aceptada.

La suite de tests pasa en las dos versiones, así que subir es un cambio de una línea en `requirements.txt` (la 5.x además necesita `invoke` 3.0.3).

### Integración continua y auditoría de dependencias

`.github/workflows/ci.yml` corre en cada push y pull request, y todos los lunes:

- `pytest` en Python 3.11, la versión del Dockerfile.
- `pip-audit` sobre `requirements.txt`. Todas las dependencias están fijadas, así que la auditoría revisa exactamente lo que instala el contenedor. La única excepción aceptada es CVE-2026-44405 (ver arriba). Cualquier otro aviso hace fallar el build.

La corrida semanal importa porque los avisos nuevos aparecen sin que cambie el código.

**Qué encontró la primera auditoría (2026-10-30).** Además de paramiko, ocho paquetes fijados tenían avisos conocidos: certifi, cryptography, filelock, idna, python-engineio, python-socketio, urllib3 y Werkzeug. Dos grupos importan más acá. idna y urllib3 están en el camino de `malware_capture.py`, que descarga URLs elegidas por el atacante (el control de SSRF es aparte y no cambia). python-engineio y python-socketio sirven el websocket del dashboard. Pasé los ocho a versiones corregidas en un solo paso, incluido `cryptography` de la 46.0.6 a la 50.0.2, que es un salto grande. Evidencia: toda la suite de tests pasa con las versiones nuevas (incluida una sesión real de paramiko) y `pip-audit` informa solo la excepción aceptada de paramiko. También comparé el paquete de intercambio de claves que manda el servidor (KEXINIT: listas de intercambio de claves, clave del host, cifrados y MAC) con `cryptography` 46.0.6 y 50.0.2, y las listas son idénticas, así que lo que ve un atacante en el handshake SSH no cambia. Lo que no cubre: todavía no corrí el contenedor reconstruido, así que el primer despliegue se mira de cerca en los logs.

Límites: `pip-audit` solo conoce avisos publicados y no dice nada sobre el código propio del honeypot.

### Login del dashboard

El dashboard pide una contraseña. Ya era accesible solo por túnel SSH, así que esto es una segunda capa: quien llegue al puerto (un túnel compartido, otro usuario del servidor, una página web que apunte a `localhost:5000`) igual necesita la contraseña.

- **Dónde vive la contraseña.** `DASHBOARD_PASSWORD` en el archivo `.env` junto a `docker-compose.yml`, fuera de git como los demás secretos. Para crear una en el servidor sin mostrarla: `echo "DASHBOARD_PASSWORD=$(openssl rand -base64 18 | tr -d '/+=')" >> .env`, y después `chmod 600 .env`.
- **Bloqueado, no abierto.** Sin contraseña configurada, todas las rutas responden 503 en vez de mostrar datos. `DASHBOARD_AUTH=off` desactiva el login a propósito, solo para desarrollo local.
- **El websocket también está cubierto.** Socket.IO atiende `/socket.io/` antes de que Flask vea el pedido, así que un chequeo de login común no lo ve. El handler de `connect` revisa la sesión y rechaza si no hay login. Los tests recorren el handshake HTTP real del protocolo, no solo el cliente de pruebas, y si se rompe ese chequeo fallan seis.
- **Cookie y fuerza bruta.** Cookie firmada, `HttpOnly`, `SameSite=Strict`, sesión de 12 horas. Cinco contraseñas incorrectas en cinco minutos bloquean el login durante un minuto.

Dos cosas que arreglé en el camino. La clave que firma las cookies era un texto fijo en el código, y el websocket aceptaba cualquier origen (`cors_allowed_origins="*"`). Ahora la clave sale de `DASHBOARD_SECRET_KEY` o es aleatoria en cada arranque, y el websocket solo acepta el mismo origen que la página.

Límites: una sola contraseña compartida, sin segundo factor, y el límite de intentos es global porque detrás del túnel todos llegan como la misma dirección. Un cliente sin login todavía puede abrir una sesión de Engine.IO, pero el servidor rechaza el namespace y no le envía nada.

### Variables de entorno

```bash
GEO_ENABLED=true              # Geolocalización de IPs (default: true)
HONEYPOT_IGNORE_IPS=          # IPs o rangos CIDR a ignorar, separados por coma
EMAIL_ENABLED=false           # Alertas por email (default: false)
EMAIL_SENDER=tu@gmail.com
EMAIL_PASSWORD=app_password
EMAIL_RECEIVER=destino@gmail.com
ALERT_THRESHOLD=5             # Intentos antes de alertar (default: 5)
ALERT_WINDOW=60               # Ventana de tiempo en segundos (default: 60)
THREAT_INTEL_ENABLED=false    # Consultas a AbuseIPDB y Shodan (default: false)
ABUSEIPDB_KEY=tu_api_key
SHODAN_KEY=tu_api_key
VIRUSTOTAL_KEY=tu_api_key
DASHBOARD_PASSWORD=           # Login del dashboard. Vacío = dashboard bloqueado (503)
DASHBOARD_SECRET_KEY=         # Opcional: firma las cookies de sesión (aleatoria en cada arranque si está vacía)
DASHBOARD_AUTH=               # off = sin login, solo para desarrollo local
```

### Qué se ve con tráfico real de internet

- Los primeros intentos llegan en minutos. No publicité el servidor en ningún lado.
- El SSH en el 2222 estuvo tranquilo. Los pocos intentos usaron usuarios por defecto y contraseñas débiles: `root`, `admin` y `user` con `123456`, `password`, `admin123`, `qwerty` y `admin`.
- El tráfico HTTP viene sobre todo de scanners que buscan paneles de administración (`/login`, `/admin`, `/wp-admin`), WordPress, Jenkins y archivos de configuración expuestos. También hubo intentos de exploit de routers GPON y pruebas de proxy abierto.
- Las IPs más activas salen de nodos de salida de Tor, rangos de VPS y bloques de IP chinos.
- Los bots son muy regulares, con milisegundos entre intentos.

El 26 de octubre, después de una semana con el puerto 22 abierto, el dashboard mostraba 2.899 eventos de 631 IPs únicas: 2.058 intentos de login SSH, 838 requests HTTP y unos pocos de FTP. Antes del puerto 22 eran 247 eventos de 111 IPs.

El total crudo engaña. Cuatro direcciones de un solo /24 hicieron 1.716 de los intentos SSH (83%). Ese bloque probablemente explica el pico de unos 900 a 950 eventos por día del 20 y 21 de octubre, aunque no revisé las fechas. También explica por qué el gráfico por día de la semana pone martes y miércoles muy por encima del resto, y probablemente por qué Francia lidera el gráfico de países con 1.781 eventos. Nada de eso muestra que los atacantes prefieran los martes o Francia. Es una sola campaña. El país es donde está registrada la IP, normalmente un proveedor de hosting, no donde está el atacante.

Fuera del pico, la actividad se estabilizó en unos 80 a 190 eventos por día, contra 60 a 70 antes del puerto 22. Creo que el puerto 22 explica el aumento, pero no separé los conteos por puerto para confirmarlo.

### Lo que aprendí armando esto

- Cómo funciona SSH por dentro: negociación de claves, autenticación y canales.
- Servidores TCP crudos con `socket` en Python, y paramiko para controlar sesiones SSH.
- Flask con WebSockets para un dashboard que se actualiza solo, y por qué recargar todo en cada evento deja de escalar.
- Entrenar e integrar un modelo de scikit-learn con datos reales.
- Consumir APIs REST y convivir con sus límites de uso (ip-api, AbuseIPDB, Shodan, VirusTotal).
- Redes en la nube y reglas de firewall, y cómo la publicación de puertos de Docker esconde la IP de origen.
- Concurrencia con `threading`.
- La parte poco glamorosa de producción: correr en segundo plano, que no se pierdan los logs, reiniciar después de una caída y sacar mi propio tráfico de los datos.
- El realismo es una carrera armamentista. Cada detalle mal hecho es algo que un scanner puede usar para identificarlo.
- Revisar lo que el honeypot no puede ver. 802 conexiones entraron y no dejaron comandos, y la razón era un manejador que faltaba en mi código, no atacantes callados.
- Una sola campaña puede distorsionar todos los gráficos. Mirá las IPs más activas antes de leer una tendencia en los totales por día o por país.
- Una regla o una función que pasa una prueba local no está en producción hasta que se despliega y un evento real pasa por ella.

### Consideraciones éticas y legales

Este proyecto es para aprender ciberseguridad. El honeypot solo captura datos de gente que intenta entrar sin permiso a un servidor que es mío. No lo uses contra sistemas ajenos ni para nada malicioso.

### Autor

Martín, soporte IT y ciberseguridad, camino a un puesto de SOC L1.

[GitHub](https://github.com/TinchoLay) · [LinkedIn](https://www.linkedin.com/in/martin-chancalay-902b543a8)
