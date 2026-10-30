# Hipótesis del honeypot

Registro público de lo que voy infiriendo de lo que llega al honeypot. Cada entrada separa **evidencia** (está en el log) de **inferencia** (lo que deduzco), dice qué la confirmaría y qué la refutaría, y no se borra si resulta falsa: las hipótesis equivocadas también enseñan.

Reglas que me impongo:
- No publico IPs ni identificadores derivados de ellas. Las redes se describen por tipo ("un proveedor de alojamiento en Países Bajos"), no por nombre, porque el registro dice quién alquila la infraestructura, no quién la usa.
- Una regla de detección se escribe cuando el patrón aparece en varios días o desde varias IPs, no con un solo caso.
- Los cambios del honeypot cortan la serie de datos y se anotan en el [CHANGELOG](CHANGELOG.md). La ventana de medición empezó el 2026-10-29 a las 20:03:21 UTC.
- Advertencias de siempre: una campaña grande puede dominar cualquier estadística, la geolocalización dice dónde está registrada una IP y no dónde está la persona, y mi honeypot acepta contraseñas débiles a propósito, así que "entró" no dice nada de lo fácil que es entrar a un sistema real.

Última actualización: 2026-10-30.

---

## H-001 · Visitantes lentos que prueban una credencial por visita
**Estado:** abierta, reforzada · **Confianza:** media-baja

**Evidencia**
- Una IP de una nube pública visitó el honeypot en 4 días distintos (22, 25, 26 y 29 de octubre) con una credencial distinta cada vez, sesiones de 2 a 3 segundos y ningún comando.
- En el resumen del 30 de octubre aparecen al menos 6 IPs más con la misma forma: mismo banner de cliente, una credencial por visita, visitas separadas por días. Son redes distintas.
- Algunas contraseñas se repiten entre IPs distintas (por ejemplo `123qwe` y `123123`), y algunos usuarios también (`blank`, `nobody`).
- Ocho de estas visitas terminaron con la contraseña débil aceptada y la IP desconectándose sin ejecutar nada.

**Inferencia (no confirmada)**
- Podría ser una lista de credenciales repartida entre muchas IPs, con un intento por IP para no superar umbrales. La contraseña repetida entre IPs apoya esa idea.
- También podría ser muestreo: una red enorme donde cada IP vuelve de vez en cuando. Con pocos días no puedo distinguirlo.
- El banner de cliente es el más común de todo el log, así que por sí solo no distingue nada. Lo que distingue es el ritmo.

**Qué la confirmaría:** una IP que entre con una credencial que ya "tuvo éxito" desde otra, o más IPs con el mismo ritmo y la misma lista.
**Qué la refutaría:** que el ritmo lento resulte indistinguible de visitas al azar al compararlo con la distribución real de IPs.

**Alerta posible (todavía no escrita):** IP vista en 3 o más días con pocos intentos por día. Técnicas: T1110.001, T1110.003, T1078. Se evade rotando de IP en cada visita, que es justo lo que podría estar pasando. Falta ventana para decidir cómo implementarla (una ventana larga en Wazuh o una lista de IPs ya vistas actualizada por script).

---

## H-002 · Monitor periódico de proxy abierto
**Estado:** abierta · **Confianza:** media en la descripción, baja en la causa

**Evidencia**
- Una IP de un operador de telecomunicaciones de Brasil hizo 12 peticiones GET a una URL absoluta de otro sitio (`hxxp://a7x[.]overflow[.]biz/hachk[.]php`) entre el 26 y el 30 de octubre, con intervalos irregulares de horas. Varias llevan el User-Agent `proxy-prefilter/1`.
- El 30 de octubre hubo 4 peticiones en unas 10 horas, más seguidas que en los días anteriores.

**Inferencia (no confirmada)**
- Parece una comprobación de si el servidor funciona como proxy abierto, repetida para saber si sigue vivo. El nombre "prefilter" sugiere una lista de proxies que se filtra antes de usarla. El aumento de frecuencia puede ser real o ruido con 12 puntos.

**Alerta posible:** petición HTTP con URL absoluta hacia otro host, repetida 3 o más veces por la misma IP en un día. Prioridad baja: no hay daño ni escalada observada.

---

## H-003 · Sondeo anti-honeypot contra el intérprete de comandos
**Estado:** abierta · **Confianza:** media en el comportamiento, baja en la causa

**Evidencia**
- Una IP de un proveedor de alojamiento de Países Bajos, con cliente SSH escrito en Go, visitó el honeypot el 22 de octubre (probando `1`, `12`, `123` como contraseñas de root) y volvió el 30 de octubre con el intérprete de comandos nuevo.
- Ese día, con dos contraseñas distintas que el honeypot aceptó, corrió dos veces la misma batería de chequeos: aritmética con números al azar, `$$`, funciones, `set --`, y un marcador único por comando, repetidos con `sh`, `bash`, `dash`, `ash`, `busybox`, `ksh` y `zsh`, con y sin ruta absoluta.
- Ninguna batería fue seguida por una carga útil. La IP se fue y no volvió en unas 13 horas.
- Una regla de mi pack (100369) ya detecta estos marcadores. No hace falta regla nueva.

**Inferencia (no confirmada)**
- Prueba si el shell es real y qué intérpretes tiene. Que dos contraseñas distintas funcionen puede ser parte de lo que lo delata, porque un servidor real acepta una sola. Puede haber concluido que es un honeypot, o su segunda etapa no se ve en lo que registro.
- No sé cómo contestó mi intérprete a la batería completa: los logs guardan comandos, no respuestas.

**Qué la confirmaría:** que vuelva con una segunda etapa, o que otra IP de su red lo haga.

---

## H-004 · Una contraseña aleatoria como detector de "acepta todo"
**Estado:** abierta · **Confianza:** media-baja (3 casos, 2 herramientas)

**Evidencia**
- Tres IPs distintas, con dos clientes SSH distintos, probaron una contraseña que nunca se había visto: dos parecen generadas al azar y una deriva del nombre de usuario. Las tres fueron rechazadas.
- Una de ellas entró antes con una contraseña débil y ejecutó por `exec` un comando de RouterOS (el sistema de MikroTik), y dos segundos después probó la contraseña aleatoria en otra conexión.

**Inferencia (no confirmada)**
- Un servidor que acepta cualquier contraseña es casi seguro un honeypot, y probar una contraseña improbable es un detector barato. Mi honeypot pasa ese chequeo porque rechaza lo improbable, pero acepta varias contraseñas débiles, y eso también puede delatarlo.
- El comando de RouterOS sugiere búsqueda de routers MikroTik por SSH. Es un solo caso.

**Qué la confirmaría:** más casos de contraseñas aleatorias o derivadas del usuario junto a una que entró.

**Idea para después de la ventana de medición:** aceptar una sola contraseña por IP en lugar de una lista de débiles, para parecerse más a un servidor real. No se toca mientras corre la medición.
