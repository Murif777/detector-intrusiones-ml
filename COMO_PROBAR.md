# Cómo probar el NIDS-ML — guía de la rama `Anderson`

Esta guía explica cómo descargar y ejecutar **la versión actual de la rama
`Anderson`**: un NIDS (sistema de detección de intrusiones) con un modelo
**Random Forest** que clasifica tráfico en tiempo real, un atacante que lanza
**tres ataques reales** dentro de Docker, alertas en la terminal y un **panel web**
que se actualiza solo.

No necesitás Python, ni `uv`, ni saber programar. Todo corre en contenedores.

> ⚠️ **La rama `main` NO tiene esta versión.**
> El menú `demo-menu.ps1`, el selector de ataques y el panel en vivo son de la
> rama **`Anderson`**. Si clonás el repo sin `-b Anderson`, el menú no va a
> existir. La sección [Descargar esta versión](#descargar-esta-versión-rama-anderson)
> explica las dos formas de bajar la rama correcta.

**Tiempo estimado:** 10–20 minutos la primera vez (casi todo es descargar
imágenes). Las siguientes veces, 2–3 minutos.

---

## Qué es el proyecto y qué vas a ver

El proyecto simula una red pequeña dentro de tu PC y demuestra la detección de
intrusiones de punta a punta:

| Pieza | Qué es | Qué hace |
|---|---|---|
| `victim` | Un servidor web nginx de prueba | Es el objetivo de los ataques. No está publicado a tu red. |
| `attacker` | Un contenedor Kali con `hping3`, `nmap` y `curl` | Lanza tres familias de ataque contra `victim`. |
| `nids` | El detector, escrito en Python con Scapy y scikit-learn | Captura el tráfico real, lo agrupa en flujos y los clasifica con un Random Forest. |
| `dashboard` | Un panel Streamlit | Muestra las alertas en el navegador y se refresca cada 2 segundos. |
| `demo-menu.ps1` | Un menú en PowerShell | Levanta todo, lanza los ataques de a uno y muestra el resumen. |

Cuando lo corras vas a ver, en este orden:

1. El menú verifica Docker y levanta `victim`, `nids` y `dashboard`.
2. Elegís un ataque (o los tres).
3. El atacante ejecuta el ataque y muestra su progreso en la terminal.
4. El detector imprime líneas `ALERTA score=...` y escribe cada alerta en
   `output/alertas.jsonl`.
5. El panel web muestra las alertas en una tabla, sin recargar la página.

Todo ocurre en una red interna de Docker (`nidsnet`). **No se ataca nada fuera
de tu computador.**

---

## Requisitos

| Requisito | Detalle |
|---|---|
| Sistema operativo | Windows 10 u 11 de 64 bits |
| Terminal | PowerShell 5.1 o superior (el que viene con Windows) |
| Docker | **Docker Desktop abierto y con el motor corriendo** (ballena estable, sin girar) |
| Internet | Solo la primera vez, para descargar las imágenes (unos **1.8 GB**) |
| Espacio en disco | Unos 2–3 GB libres, además de lo que ocupe Docker Desktop |
| Python / `uv` / Node | **No hacen falta para probar.** Todo corre dentro de Docker |
| Permisos | No necesitás ejecutar la demo como administrador. Instalar Docker Desktop sí puede pedir permisos |

Tamaño aproximado de las imágenes que se descargan la primera vez:

| Imagen | Tamaño |
|---|---|
| `detector-intrusiones-ml` (NIDS + dashboard + modelo) | 1.44 GB |
| `detector-intrusiones-ml-attacker` (Kali + herramientas) | 264 MB |
| `nginx:alpine` (víctima) | 103 MB |

> 💡 La imagen del NIDS **ya trae el modelo entrenado adentro**. No hay que
> entrenar nada ni descargar el dataset NSL-KDD para probar la demo.

---

## Descargar esta versión (rama `Anderson`)

### Opción A — con Git (recomendada)

Abrí PowerShell y ejecutá:

```powershell
git clone -b Anderson https://github.com/Murif777/detector-intrusiones-ml.git
cd detector-intrusiones-ml
```

El `-b Anderson` es lo que baja la rama correcta. Sin ese parámetro, Git baja
`main`, que **no** tiene el menú ni el selector de ataques.

### Opción B — con ZIP (sin instalar Git)

1. Entrá a **https://github.com/Murif777/detector-intrusiones-ml**
2. Arriba a la izquierda vas a ver un selector de rama que dice **`main`**.
   Hacé clic y elegí **`Anderson`**.
3. Hacé clic en el botón verde **`< > Code`** → **Download ZIP**.
4. Extraé el ZIP en una carpeta fácil de encontrar, por ejemplo `C:\nids`.
   El nombre de la carpeta suele ser `detector-intrusiones-ml-Anderson`.
5. Entrá a esa carpeta y verificá que adentro estén `docker-compose.yml` y
   `demo-menu.ps1`.

### Si ya tenías el repo clonado en `main`

```powershell
cd detector-intrusiones-ml
git fetch origin
git switch Anderson
git pull --ff-only origin Anderson
```

Si tu Git es viejo y no tiene `switch`, usá `git checkout Anderson`.

### Verificación rápida

En la carpeta del repo:

```powershell
git branch --show-current    # tiene que decir: Anderson
Test-Path .\demo-menu.ps1    # tiene que decir: True
Test-Path .\docker-compose.yml
```

Si `demo-menu.ps1` no existe, estás en `main` o en la carpeta equivocada.
Volvé al paso de descarga.

---

## Abrir PowerShell en la carpeta correcta

1. Abrí la carpeta del proyecto en el **Explorador de archivos**.
2. Confirmá que **adentro** se vean `docker-compose.yml` y `demo-menu.ps1`.
3. Hacé clic en la **barra de direcciones** de arriba, borrá lo que haya y
   escribí:

   ```
   powershell
   ```

4. Presioná **Enter**.

Se abre una ventana de PowerShell ya ubicada en esa carpeta.

> 💡 También podés hacer clic derecho en un espacio vacío de la carpeta →
> **"Abrir en Terminal"** (Windows 11) o **"Abrir ventana de PowerShell aquí"**
> (Windows 10).

Verificación:

```powershell
dir
```

Tienen que aparecer `docker-compose.yml` y `demo-menu.ps1`. Si no aparecen,
estás en otra carpeta.

---

## Arrancar el menú (camino recomendado)

Con Docker Desktop abierto, ejecutá:

```powershell
powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1
```

Qué hace ese comando:

- `powershell` abre Windows PowerShell.
- `-ExecutionPolicy Bypass` permite ejecutar **este script en esta corrida**.
  No cambia la configuración del sistema.
- `-File .\demo-menu.ps1` ejecuta el menú que está en la carpeta actual.

> ⚠️ Si escribís solamente `.\demo-menu.ps1`, Windows puede bloquearlo con el
> error de "ejecución de scripts deshabilitada". Usá el comando completo de
> arriba.

### Qué hace el menú, paso a paso

1. Verifica que exista el comando `docker` y que Docker responda
   (`docker info`). Si no responde, muestra un mensaje y termina.
2. Fija `NIDS_DURATION=0` para que el detector **no se corte a los 90 segundos**
   y pueda encadenar varios ataques.
3. Levanta `victim` y `nids` en segundo plano y espera a que el detector
   confirme que está capturando (`Capturando en eth0`).
4. Levanta `dashboard` y espera hasta 60 segundos a que responda.
5. **Muestra el link `http://localhost:8501` pero NO abre el navegador.**
   Ese link lo abrís vos.
6. Presenta el menú y espera tu elección.

La primera vez puede tardar varios minutos porque descarga las imágenes.
Después es casi instantáneo.

Vas a ver algo así:

```text
================================================================
  NIDS-ML · Demo interactiva (solo Docker)
================================================================
  Verificá Docker, levantá el detector y lanzá ataques de a uno.
[..] Asegurando victim y nids (detector indefinido)...
[OK] victim y nids arriba (NIDS_DURATION=0).
[..] Levantando el dashboard...
[OK] Dashboard listo.
    Abrí el panel en: http://localhost:8501

================================================================
  NIDS-ML · Menú de demostración
================================================================
  Dashboard: http://localhost:8501

  1) SYN flood          (perfil neptune: SYNs sin respuesta)
  2) Escaneo de puertos (perfil nmap)
  3) Inundación HTTP    (perfil satan)
  4) Los tres ataques
  5) Salir
```

---

## Usar el menú

| Opción | Ataque | Perfil de NSL-KDD | Qué hace |
|---|---|---|---|
| `1` | SYN flood | `neptune` | 400 SYN a `victim:80`, con orígenes falsos y sin respuesta. |
| `2` | Escaneo de puertos | `nmap` | Escaneo SYN de 300 puertos desde un mismo origen. |
| `3` | Inundación HTTP | `satan` | 60 peticiones POST con carga, esperando respuesta. |
| `4` | Los tres ataques | `neptune + nmap + satan` | Ejecuta los tres, espaciados en el tiempo. |
| `5` | Salir | — | Sale del menú y pregunta si querés apagar la demo. |

Al elegir una opción vas a ver el **progreso del atacante en vivo** en esa misma
terminal. Por ejemplo, con la opción `4`:

```text
==============================================
 ATACANTE - objetivo: victim
 Ataque(s): all
==============================================
NIDS_WARMUP=0: arrancando sin espera inicial.

>>> [1/3] SYN flood (perfil neptune)
    SYN flood terminado (400 paquetes)

>>> [2/3] Escaneo de puertos (perfil nmap)
    Escaneo terminado (300 puertos)

>>> [3/3] Inundacion HTTP (perfil satan)
    Flood HTTP terminado (60 peticiones)

==============================================
 Ataques completados. Revisa la salida del NIDS.
==============================================
```

> ℹ️ Con un solo ataque (`1`, `2` o `3`) no aparece el contador `[x/3]` y el
> cierre dice `Ataque completado.` en singular. El contador aparece con `4`
> (o con `-Attack all`).

### Dónde ver las líneas `ALERTA`

El menú corre el atacante en primer plano, pero **el detector corre en segundo
plano**. Por eso las líneas crudas del NIDS no salen en la terminal del menú:
salen en los logs del contenedor y, sobre todo, en el panel web.

Si querés proyectarlas en otra terminal:

```powershell
docker compose logs -f nids
```

Vas a ver, mientras ataca:

```text
nids-detector  | ALERTA score=0.797 tcp/http flag=S0 src_bytes=0 serror=1.00
nids-detector  | ALERTA score=0.797 tcp/http flag=S0 src_bytes=0 serror=1.00
nids-detector  | ALERTA score=0.797 tcp/http flag=S0 src_bytes=0 serror=1.00
```

El `score` y el `flag` varían según el flujo. La señal de que todo funciona es
que aparezcan líneas que empiecen con `ALERTA`.

### Resumen al terminar cada ataque

El menú detiene el NIDS unos segundos para que vuelque las alertas pendientes
(por ejemplo, los SYN que nunca recibieron respuesta) y después lo vuelve a
levantar. Por eso vas a ver estas líneas y luego el resumen:

```text
[..] Volcando alertas pendientes (deteniendo nids de forma limpia)...
[..] Reiniciando el detector para el proximo ataque...

  RESUMEN
  ------------------------------------------------------
    Ataque          : Los tres ataques
    Alertas nuevas  : 44
    Duración aprox. : 19,7 s

  RESULTADOS
  ------------------------------------------------------
    Últimas 10 alerta(s) nuevas:
    hora       veredicto   score  detalle
    12:23:51   ATAQUE      0,797  tcp/http flag=S0 count=1
    12:23:51   ATAQUE      0,797  tcp/http flag=S0 count=1
    ...

    Detalle completo: http://localhost:8501
```

Los números de `Alertas nuevas` y `Duración` **cambian en cada corrida**. Lo
importante es que `Alertas nuevas` sea mayor que cero. Si da cero, el menú
muestra "No se registraron alertas nuevas." y una pista para revisar.

La columna `detalle` del menú usa el formato
`protocolo/servicio flag=... count=...`. El detalle completo, con bytes y tasa
de error, está en el panel.

### Preguntas del menú

Después de cada ataque:

```text
  ¿Volver al menú? (s/n)
```

- **`s`** → vuelve al menú para lanzar otro ataque.
- **`n`** → sale del menú y pasa a la pregunta final.

La pregunta final es:

```text
  ¿Apagar la demo? (s/n)
```

- **`s`** → ejecuta `docker compose down` y apaga todo.
- **`n`** → deja la demo corriendo y muestra el link del panel.

La opción `5` del menú también llega a esta pregunta final.

> 💡 Si apretás **Ctrl+C** durante la demo, el script avisa
> "Demo interrumpida (Ctrl+C)." y sale, pero **los contenedores siguen
> corriendo**. En ese caso apagalos a mano con `docker compose down`.

Ni la opción `5` ni responder `n` a la pregunta de apagado borra las alertas:
quedan en `output/alertas.jsonl` y el panel las sigue mostrando mientras esté
arriba.

---

## Modo rápido sin menú

Si querés lanzar un ataque y salir, sin menú ni preguntas:

```powershell
powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1 -Attack 1
```

Valores posibles:

| Valor | Ataque |
|---|---|
| `1` | SYN flood |
| `2` | Escaneo de puertos |
| `3` | Inundación HTTP |
| `all` | Los tres ataques |

Ejemplos:

```powershell
powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1 -Attack 3
powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1 -Attack all
```

Qué hace este modo:

- Verifica Docker y levanta **solo `victim` y `nids`** (no levanta el dashboard).
- Lanza el ataque elegido y muestra su progreso.
- Detiene el NIDS para volcar las alertas, lo vuelve a levantar y muestra el
  resumen.
- **No pregunta nada** y termina solo.
- Deja el detector corriendo (`NIDS_DURATION=0`) y los contenedores arriba.
- Si el dashboard ya estaba corriendo de antes, imprime su link al final.

Para ver el panel después de este modo:

```powershell
docker compose up -d dashboard
```

Y para apagar todo cuando termines:

```powershell
docker compose down
```

---

## Panel web

Abrí tu navegador (Chrome, Edge, Firefox, el que uses) en:

**http://localhost:8501**

El menú muestra ese link, pero no abre el navegador automáticamente.

### Qué muestra

De arriba hacia abajo, el panel muestra: el subtítulo **"Alertas en tiempo
real"**, la línea de **última actualización**, las cuatro tarjetas de métricas,
el estado del detector, las métricas del modelo (si existen), la tabla de
alertas y la leyenda de flags.

Las cuatro tarjetas son:

| Tarjeta | Qué significa |
|---|---|
| **Modelo entrenado** | `sí` si el artefacto del modelo está dentro de la imagen. |
| **Eventos totales** | Cantidad de alertas guardadas en `output/alertas.jsonl` (incluye corridas anteriores). |
| **Detectados como ataque** | Cuántas de esas alertas tienen veredicto `ATAQUE`. |
| **Tráfico normal** | Cuántas tienen veredicto `NORMAL`. |

> ℹ️ En esta demo el detector **solo persiste los flujos que marcó como ataque**.
> Por eso `Eventos totales` y `Detectados como ataque` suelen coincidir, y
> `Tráfico normal` queda en `0`. No es un error del panel: el store guarda
> únicamente las alertas.

Debajo aparece el estado del detector:

- **🟢 Capturando en vivo (última alerta hace N s)** cuando la última alerta
  tiene menos de 15 segundos.
- **⚪ Detector detenido o sin captura reciente** cuando no hay alertas o la
  última es más vieja que 15 segundos. Es una heurística, no un chequeo de
  salud del contenedor: después de un ataque es normal que pase a ⚪.

Si el artefacto incluye `models/metrics.json` (la imagen publicada lo incluye),
el panel agrega una sección **"Métricas del modelo"** con `accuracy`,
`precision`, `recall`, `f1` y `roc_auc` del último entrenamiento. Son métricas
medidas sobre el dataset, no sobre la demo.

La línea de actualización se ve así:

```text
Última actualización: 12:23:53 (hora local) · se refresca cada 2s.
```

### Se actualiza solo

El panel usa un fragmento de Streamlit que se ejecuta cada **2 segundos**. No
hace falta recargar ni apretar F5: durante un ataque vas a ver las filas
aparecer solas.

Si el navegador quedó con una versión vieja, hacé **Ctrl + F5** una vez.

### Hora local y zona horaria

Las horas del panel se muestran en la zona horaria **del contenedor**, no
necesariamente en la de tu PC. Por defecto es:

```text
America/Bogota
```

Se puede cambiar con la variable `DEMO_TZ`, en la misma sesión de PowerShell,
antes de levantar el dashboard:

```powershell
$env:DEMO_TZ = "America/Lima"
docker compose up -d dashboard
```

`docker compose` recrea el contenedor del panel para tomar la variable. Para
volver al valor por defecto:

```powershell
Remove-Item Env:DEMO_TZ -ErrorAction SilentlyContinue
docker compose up -d dashboard
```

> ℹ️ La tabla del **menú** usa la hora local de Windows; la del **panel** usa la
> zona del contenedor. Si tu PC está en otra zona, pueden diferir.

### Tabla de alertas

Muestra las **200 alertas más recientes**, primero las más nuevas. Columnas:

| Columna | Qué es |
|---|---|
| `hora` | Hora local del evento (`HH:MM:SS`). |
| `veredicto` | `ATAQUE` (o `NORMAL`, si alguna vez se persistió uno). |
| `score` | Probabilidad de ataque, de 0 a 1. |
| `protocolo` | `tcp`, `udp`, `icmp`... |
| `servicio` | Servicio inferido (`http`, `other`...). |
| `flag` | Estado de la conexión TCP. |
| `bytes origen` | Bytes enviados por el origen. |
| `bytes destino` | Bytes enviados por el destino. |
| `paquetes` | Paquetes del flujo. |
| `serror` | Tasa de intentos fallidos (SYN sin respuesta, etc.). |

Leyenda de `flag`:

| Flag | Significado |
|---|---|
| `S0` | SYN sin respuesta: se intentó abrir una conexión y nadie contestó. |
| `S1` | Conexión establecida. |
| `SF` | Conexión normal: abierta y cerrada correctamente. |
| `REJ` | Conexión rechazada. |

`score` es la probabilidad de ataque (0 a 1) y `serror` la tasa de intentos
fallidos. Un SYN flood típico deja filas con `flag=S0`, `src_bytes=0` y
`serror=1.00`.

Si ves **"Sin alertas todavía"**, todavía no corrió ningún ataque. Lanzá una
opción del menú y esperá unos segundos.

### Si el panel no carga

- Verificá que el contenedor esté arriba:

  ```powershell
  docker compose ps
  ```

- Mirá sus logs:

  ```powershell
  docker compose logs --tail 80 dashboard
  ```

- Confirmá que el puerto 8501 esté libre (ver [Problemas comunes](#problemas-comunes)).
- Esperá hasta 60 segundos después de levantarlo: Streamlit tarda en arrancar.

---

## Flujo manual alternativo (sin menú)

El menú es el camino recomendado porque encadena ataques y cuenta las alertas
nuevas. Si preferís hacerlo a mano, estos son los comandos equivalentes.

**Terminal A — levantar todo:**

```powershell
docker compose up
```

Eso levanta `victim`, `nids`, `attacker` y `dashboard`. El atacante espera 12
segundos (para que el NIDS esté capturando) y lanza los tres ataques. El NIDS
captura durante 90 segundos y al terminar imprime su tabla `Resumen en vivo`.

**Terminal B — ver solo las alertas del detector:**

```powershell
docker compose logs -f nids
```

**Terminal C (o después de bajar la Terminal A) — asegurar el panel:**

```powershell
docker compose up -d dashboard
```

> ℹ️ `docker compose up` ya incluye el dashboard, así que el tercer comando
> solo hace falta si levantaste nada más `victim` y `nids`, o si el panel se
> cayó. Es idempotente: si ya está arriba, no lo duplica.

Para cortar el flujo manual: **Ctrl+C** en la Terminal A y después
`docker compose down`.

---

## Apagar todo

La forma limpia:

```powershell
docker compose down
```

Eso detiene y elimina los contenedores y la red de la demo. **No borra** las
alertas de `output/alertas.jsonl` ni las imágenes descargadas, así que la
próxima corrida es rápida.

También podés apagar desde el menú: respondé **`s`** a
`¿Apagar la demo? (s/n)`.

Verificación:

```powershell
docker compose ps
```

No debería quedar ningún contenedor de `detector-intrusiones-ml` corriendo.

---

## Problemas comunes

| Síntoma | Causa probable | Qué hacer |
|---|---|---|
| `docker: no se reconoce como comando...` | Docker no está instalado o no está en el PATH | Instalá Docker Desktop, reiniciá la terminal y volvé a probar. |
| `[!] Docker no responde.` o `Cannot connect to the Docker daemon` | Docker Desktop está cerrado o todavía arrancando | Abrí Docker Desktop y esperá a que el motor esté corriendo (ballena estable). |
| `No se encuentra el archivo .\demo-menu.ps1` | Estás en `main`, en otra carpeta o el ZIP se extrajo mal | Verificá `Test-Path .\demo-menu.ps1`. Si da `False`, cloná con `-b Anderson` o cambiá de rama. |
| `... no se puede cargar porque la ejecución de scripts está deshabilitada...` | Política de ejecución de PowerShell | Usá el comando completo: `powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1`. |
| Se queda mucho tiempo en `Pulling` / `Downloading` | Primera descarga de imágenes (~1.8 GB) | Es normal: puede tardar 5–15 minutos. No canceles. |
| El primer ataque tarda en arrancar | Se está descargando la imagen del atacante (264 MB) | Esperá. Solo pasa la primera vez. |
| `Bind for 0.0.0.0:8501 failed: port is already allocated` | Otro programa (u otro dashboard) usa el puerto 8501 | `docker compose down`, cerrá el otro Streamlit y reintentá. Para identificar el proceso: `Get-NetTCPConnection -LocalPort 8501 -ErrorAction SilentlyContinue`. |
| `[!] El dashboard no respondió en 60 s` | Streamlit todavía arranca o hay conflicto de puerto | Esperá y revisá `docker compose logs dashboard`. El menú sigue funcionando sin panel. |
| `[!] El NIDS no confirmó que esté capturando` | El contenedor recién arranca o falló la captura | `docker compose logs nids`; esperá unos segundos; si persiste, `docker compose down` y reintentá. |
| `Alertas nuevas: 0` / no aparece ninguna `ALERTA` | El ataque no llegó a tiempo o el detector se reinició | Probá `-Attack 1` de nuevo. Revisá `docker compose logs nids`. Si sigue, `docker compose down` y volvé a empezar. |
| El panel muestra datos viejos o "Eventos totales" muy alto | `output/alertas.jsonl` es acumulativo entre corridas | Es normal. Para empezar de cero, con el stack detenido, borrá ese archivo (ver la nota de abajo). |
| Todo se ve raro después de una corrida anterior | Quedaron contenedores viejos | `docker compose down`, esperá 5 segundos y levantá de nuevo. |
| Windows pregunta por el firewall | Docker publica el puerto 8501 | Permití el acceso en redes privadas. |

### La solución universal

Si nada funciona, esto resuelve la mayoría de los casos:

```powershell
docker compose down
```

Esperá 10 segundos, cerrá y volvé a abrir Docker Desktop, esperá a que arranque
y repetí el comando del menú.

### Sobre `output/alertas.jsonl`

El archivo de alertas es **append-only**: cada corrida agrega líneas y nunca se
reescribe. Por eso:

- El menú muestra **solo las alertas nuevas** de cada ataque (cuenta las líneas
  del archivo antes y después).
- El panel muestra **todo el histórico** en `Eventos totales`.
- Si querés un contador limpio, primero apagá el stack y después borrá el
  archivo:

  ```powershell
  docker compose down
  Remove-Item .\output\alertas.jsonl
  ```

  **No lo borres con la demo corriendo** y avisá si es un archivo compartido.

---

## Qué hay dentro y cómo funciona

### Topología

```text
Tu PC (Windows + Docker Desktop)
└── Red interna de Docker: nidsnet (bridge, aislada de tu red real)
    ├── victim     nginx:alpine, sin puertos publicados al host
    ├── nids       detector: captura en eth0, clasifica y escribe alertas
    ├── attacker   Kali: hping3 + nmap + curl, comparte la red del NIDS
    └── dashboard  Streamlit: único puerto publicado (8501)
```

El atacante usa `network_mode: "service:nids"`, es decir, **comparte el espacio
de red del NIDS**. ¿Por qué? Porque un bridge de Docker solo entrega el tráfico
al puerto de destino: un tercer contenedor no vería el ataque. Al compartir la
interfaz, los paquetes del atacante salen por la misma `eth0` que el detector
captura. La captura es real y no depende de configurar modo promiscuo en el
host.

### Cada pieza

- **`victim`**: servidor nginx de prueba. No tiene puertos publicados; solo es
  alcanzable desde `nidsnet`.
- **`nids`**: corre `scripts/live_nids.py`. Carga el modelo desde la imagen,
  imprime `modelo: random_forest   umbral: 0.05`, captura con Scapy en `eth0`,
  agrupa paquetes en ventanas de **2 segundos** (y una ventana de host de 100
  segundos), arma el vector con las 23 features soportadas por flujo (20
  numéricas + 3 categóricas) y clasifica. Si el score supera el umbral, imprime
  `ALERTA ...` y agrega una línea JSON a
  `output/alertas.jsonl`.
- **`attacker`**: corre `docker/attack.sh`. Lanza 400 SYN (SYN flood), un
  escaneo SYN de 300 puertos y 60 peticiones HTTP. Cada ataque tiene `timeout`:
  si una herramienta se traba, el script sigue y la demo no se cuelga.
- **`dashboard`**: Streamlit dentro de la misma imagen del NIDS. Lee el JSONL
  cada 2 segundos y dibuja las métricas y la tabla. **Solo lee**, no escribe.
- **`demo-menu.ps1`**: orquestador en PowerShell. No usa Python del host:
  ejecuta `docker compose`, cuenta líneas del JSONL y muestra el resumen.

### El modelo y el umbral 0.05

- **Random Forest** de 300 árboles, con `class_weight="balanced"`.
- Usa **23 de las 41 features** de NSL-KDD (20 numéricas + 3 categóricas). Las
  otras 18 no se pueden derivar del tráfico capturado en vivo; quedan en 0 y
  están documentadas. No se inventan features.
- **Umbral de decisión: 0.05**, no el 0.5 que usa scikit-learn por defecto.
  Es una decisión deliberada: en un NIDS, una alerta de más se revisa; un ataque
  perdido no se recupera. Con 0.5 el recall bajaba a 0.64 (se perdía un tercio
  de los ataques).
- El modelo viaja **dentro de la imagen** junto con el encoder. No hay una
  segunda implementación de features que pueda divergir entre entrenamiento e
  inferencia.

Métricas sobre `KDDTest+.txt` (22 544 flujos que el modelo nunca vio):

| Métrica | Valor |
|---|---|
| Accuracy | 0.9310 |
| Precision | 0.9254 |
| Recall | 0.9559 |
| F1 | 0.9404 |
| ROC-AUC | 0.9595 |

> ⚠️ La demo en vivo usa tráfico generado para ilustrar el mecanismo. Las
> métricas de arriba salen de la evaluación sobre el dataset, no de la demo.

---

## Para agentes de IA

Esta sección está pensada para que un agente **sin contexto previo** pueda
levantar, ejecutar y verificar la demo sin intervención humana. Seguí las
verificaciones en orden y no improvises rutas ni comandos.

### Objetivo

1. Confirmar que el repo está en la rama `Anderson` y en la carpeta correcta.
2. Levantar `victim`, `nids` y ejecutar los tres ataques.
3. Confirmar que el NIDS emite alertas y escribe `output/alertas.jsonl`.
4. Confirmar que el panel responde HTTP 200 en `http://localhost:8501`.
5. Reportar el resultado. **No modificar código para "hacer que funcione".**

### 1. Verificaciones previas

Ejecutá esto en PowerShell, desde la raíz del repo:

```powershell
# 1. Carpeta correcta: ambos deben imprimir True
Test-Path .\docker-compose.yml
Test-Path .\demo-menu.ps1

# 2. Rama correcta: debe imprimir Anderson
git branch --show-current

# 3. Docker responde: debe imprimir algo como Server=29.7.2
docker info --format 'Server={{.ServerVersion}}'
```

Interpretación:

| Resultado | Acción |
|---|---|
| `Test-Path` devuelve `False` | Estás en otra carpeta. `cd` a la raíz que contiene `docker-compose.yml` y `demo-menu.ps1`. |
| La rama no es `Anderson` | `git fetch origin`, `git switch Anderson`, `git pull --ff-only origin Anderson`. **Nunca** cambiar a `main` para "probar". |
| `docker info` falla o no responde | Abrí Docker Desktop y esperá hasta 120 segundos. Reintentá. Si sigue fallando, detenete y reportá; no intentes instalar Docker. |
| `docker info` responde | Continuá. |

Opcional, para saber si hay contenedores de una corrida anterior:

```powershell
docker compose ps
```

Si hay contenedores viejos y la corrida anterior falló, empezá limpio con
`docker compose down` (no borra alertas).

### 2. Ejecución

**Modo recomendado para un agente (no interactivo):**

```powershell
powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1 -Attack all
```

- Ejecuta los tres ataques y termina solo.
- No abre el dashboard (solo levanta `victim` y `nids`).
- Tarda aproximadamente 20–90 segundos después de tener las imágenes.
- La primera vez puede tardar 5–15 minutos más por la descarga (~1.8 GB).

Ataques individuales:

```powershell
powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1 -Attack 1   # SYN flood
powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1 -Attack 2   # escaneo
powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1 -Attack 3   # HTTP flood
```

**Modo interactivo (solo si hay un humano presente):**

```powershell
powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1
```

Ese modo espera entrada por teclado (`1`–`5`, `s`/`n`). **No lo uses en
automatización**: se quedaría esperando.

### 3. Salidas esperadas

Con `-Attack all`, la salida debe contener estos hitos:

```text
[..] Modo automático: un solo ataque (all), sin menú.
[..] Asegurando victim y nids (detector indefinido)...
[OK] victim y nids arriba (NIDS_DURATION=0).

>>> [1/3] SYN flood (perfil neptune)
    SYN flood terminado (400 paquetes)

>>> [2/3] Escaneo de puertos (perfil nmap)
    Escaneo terminado (300 puertos)

>>> [3/3] Inundacion HTTP (perfil satan)
    Flood HTTP terminado (60 peticiones)

==============================================
 Ataques completados. Revisa la salida del NIDS.
==============================================
```

Después del ataque, el menú detiene el NIDS para volcar las alertas y muestra:

```text
[..] Volcando alertas pendientes (deteniendo nids de forma limpia)...
[..] Reiniciando el detector para el proximo ataque...

  RESUMEN
  ------------------------------------------------------
    Ataque          : Los tres ataques
    Alertas nuevas  : 44
    Duración aprox. : 19,7 s

  RESULTADOS
  ------------------------------------------------------
    Últimas 10 alerta(s) nuevas:
    hora       veredicto   score  detalle
    12:23:51   ATAQUE      0,797  tcp/http flag=S0 count=1
    ...

    Detalle completo: http://localhost:8501
```

Los valores numéricos **no son fijos**; lo que importa es:

- Aparecen `[1/3]`, `[2/3]` y `[3/3]` (solo en modo `all`).
- Aparece `Ataques completados.` (o `Ataque completado.` con un solo ataque).
- `Alertas nuevas` es **mayor que 0**.

Las líneas crudas del detector están en el log de `nids`, no en la terminal del
menú. Verificalas así:

```powershell
docker compose logs nids | Select-String 'ALERTA' | Select-Object -Last 10
```

Debe haber al menos una línea con esta forma (el score y el flag varían):

```text
nids-detector  | ALERTA score=0.797 tcp/http flag=S0 src_bytes=0 serror=1.00
```

La tabla de cierre del detector también queda en ese log:

```powershell
docker compose logs nids | Select-String 'Resumen en vivo|paquetes capturados|flujos analizados|alertas emitidas|tasa de alerta'
```

Ejemplo de lo que imprime (los valores cambian):

```text
nids-detector  |       Resumen en vivo (62s)
nids-detector  | ┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┓
nids-detector  | ┃ metrica             ┃ valor   ┃
nids-detector  | ┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━┩
nids-detector  | │ paquetes capturados │ 1       │
nids-detector  | │ flujos analizados   │ 1       │
nids-detector  | │ alertas emitidas    │ 1       │
nids-detector  | │ tasa de alerta      │ 100.00% │
nids-detector  | └─────────────────────┴─────────┘
nids-detector  | Alertas persistidas en output/alertas.jsonl
```

> ℹ️ Esta tabla aparece cuando el proceso del NIDS termina de forma limpia. En el
> menú ocurre después de cada ataque (el script lo detiene para volcar); en el
> flujo manual ocurre a los 90 segundos.

### 4. Verificación del panel

El modo `-Attack` **no levanta el dashboard**. Para verificarlo, levantalo y
esperá hasta 60 segundos:

```powershell
docker compose up -d dashboard

$r = Invoke-WebRequest -Uri http://localhost:8501 -UseBasicParsing -TimeoutSec 20
$r.StatusCode
```

Resultado esperado: **`200`**.

> ⚠️ Revisá las líneas `ALERTA` **antes** de este paso. Si Compose recrea `nids`
> (por ejemplo, porque `NIDS_DURATION` cambia al ejecutar el comando en una
> shell nueva), el contenedor nuevo arranca con logs vacíos y las líneas del
> ataque anterior ya no aparecen en `docker compose logs nids`. El panel no se
> ve afectado porque lee el JSONL, pero el detector puede quedar con la duración
> por defecto de 90 s.

Si `Invoke-WebRequest` falla, revisá en este orden:

```powershell
docker compose ps
docker compose logs --tail 80 dashboard
Get-NetTCPConnection -LocalPort 8501 -ErrorAction SilentlyContinue
```

### 5. Criterios de éxito

La corrida se considera exitosa si se cumplen **todos** estos puntos:

- [ ] `-Attack all` termina sin errores de PowerShell.
- [ ] La salida contiene `[1/3]`, `[2/3]`, `[3/3]` y `Ataques completados.`
- [ ] La salida contiene `Alertas nuevas  : N` con `N > 0`.
- [ ] `docker compose logs nids` contiene al menos una línea `ALERTA score=`.
- [ ] El log del NIDS contiene `Resumen en vivo` (o al menos
      `alertas emitidas`).
- [ ] `Invoke-WebRequest http://localhost:8501` devuelve `200`.
- [ ] `docker compose ps` muestra `nids-victim` corriendo y, si la corrida
      acaba de terminar, también `nids-detector`.

> ⚠️ El script devuelve código de salida `0` aunque el atacante haya terminado
> con error (solo imprime una advertencia `[!] El atacante terminó con código
> N.`). Por eso **no alcanza con mirar el exit code**: verificá también las
> líneas y el conteo de alertas.

### 6. Si falla, revisar en este orden

1. **Carpeta y archivos**: `Test-Path .\docker-compose.yml` y
   `Test-Path .\demo-menu.ps1` deben dar `True`.
2. **Rama**: `git branch --show-current` debe dar `Anderson`.
3. **Docker**: `docker info --format 'Server={{.ServerVersion}}'` debe
   responder. Si no, abrir Docker Desktop y esperar.
4. **Contenedores**: `docker compose ps -a` para ver estados y reinicios.
5. **Log del detector**: `docker compose logs --tail 80 nids`. Buscar
   `modelo:`, `Capturando en eth0`, `ALERTA` y `Resumen en vivo`.
6. **Log del panel**: `docker compose logs --tail 80 dashboard`. Buscar errores
   de puerto o de arranque de Streamlit.
7. **Puerto 8501**: `Get-NetTCPConnection -LocalPort 8501 -ErrorAction SilentlyContinue`.
8. **Reinicio limpio**: `docker compose down`, esperar 5 segundos y repetir.
9. Si sigue fallando, reportar el comando exacto, la salida y los logs. **No
   parchear el código ni el compose para que "pase".**

### 7. Reglas y restricciones

- Trabajar **solo** en la rama `Anderson`. No hacer checkout, merge ni push a
  `main` (ni local ni remota).
- **Nunca** usar `git push --force` ni reescribir historia.
- **No borrar** `output/alertas.jsonl` sin autorización explícita: es
  append-only y puede contener evidencia de corridas anteriores.
- **No modificar** `demo-menu.ps1`, `docker-compose.yml`, `docker/attack.sh`,
  `dashboard.py` ni el código para "arreglar" la demo. Si algo falla, reportar.
- No atacar hosts externos: `attack.sh` apunta a `victim` dentro de `nidsnet`.
  No cambiar el objetivo ni ejecutar las herramientas de Kali contra tu red.
- No ejecutar `docker system prune`, `docker compose down -v` ni borrar
  imágenes: son destructivos y no forman parte de la prueba.
- No publicar puertos nuevos. El único puerto necesario es `8501`.
- Si hay que publicar cambios, hacerlo solo con `git push origin Anderson`.

### 8. Nota sobre el contador de alertas

`output/alertas.jsonl` es **append-only** y acumula entre corridas:

- El menú informa `Alertas nuevas` comparando el archivo antes y después de
  cada ataque.
- El panel informa `Eventos totales` con **todo** el histórico.
- Para dejar el contador en cero: con el stack **detenido**
  (`docker compose down`), borrar `output\alertas.jsonl`. Pedir autorización
  antes si el archivo es compartido.

---

## Chuleta final

| Quiero... | Comando |
|---|---|
| Descargar la rama correcta | `git clone -b Anderson https://github.com/Murif777/detector-intrusiones-ml.git` |
| Abrir PowerShell en la carpeta | escribir `powershell` en la barra de direcciones del Explorador |
| Arrancar el menú | `powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1` |
| Lanzar un ataque suelto | `powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1 -Attack 1` |
| Lanzar los tres | `powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1 -Attack all` |
| Abrir el panel | http://localhost:8501 |
| Ver las alertas crudas | `docker compose logs -f nids` |
| Ver el estado de los contenedores | `docker compose ps` |
| Apagar todo | `docker compose down` |
| Verificar Docker | `docker info --format 'Server={{.ServerVersion}}'` |
| Verificar el panel | `(Invoke-WebRequest http://localhost:8501 -UseBasicParsing).StatusCode` |

### Resumen ultra corto

```powershell
git clone -b Anderson https://github.com/Murif777/detector-intrusiones-ml.git
cd detector-intrusiones-ml
powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1
```

Elegí `4` para lanzar los tres ataques y abrí **http://localhost:8501**. Al
terminar, respondé `n` a `¿Volver al menú? (s/n)` y `s` a
`¿Apagar la demo? (s/n)`.

Eso es todo.
