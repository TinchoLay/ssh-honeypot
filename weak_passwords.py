"""Contrasenas que el honeypot acepta de entrada.

Dos fuentes, y las dos son las que usan los bots reales:
  1. Las contrasenas mas comunes de las listas publicas (tipo SecLists / NordPass /
     SplashData). Son las primeras que prueba cualquier diccionario.
  2. Credenciales por defecto de dispositivos IoT (familia Mirai): routers, camaras
     y DVR que salen de fabrica con claves conocidas.
Es una seleccion de ~50, no una copia de una lista oficial: conviene contrastarla
con las claves que realmente aparecen en logs/ y ajustarla con datos propios.
"""

MAS_COMUNES = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
    "111111", "1234567", "dragon", "123123", "baseball", "abc123", "football",
    "monkey", "letmein", "shadow", "master", "666666", "qwertyuiop", "123321",
    "mustang", "1234567890", "654321", "superman", "1qaz2wsx", "7777777",
    "121212", "000000", "qazwsx", "123qwe", "killer", "trustno1", "zxcvbnm",
    "asdfgh", "hunter", "soccer", "batman", "sunshine", "iloveyou", "princess",
    "welcome", "admin123", "password1", "qwerty123", "passw0rd", "changeme",
}

DEFAULTS_IOT_Y_SISTEMAS = {
    "admin", "root", "toor", "test", "guest", "user", "pass", "default",
    "ubuntu", "raspberry", "pi", "support", "ubnt", "oracle", "postgres",
    "xc3511", "vizxv", "888888", "54321", "juantech", "7ujMko0admin", "1234qwer",
}

CLAVES_DEBILES = MAS_COMUNES | DEFAULTS_IOT_Y_SISTEMAS
