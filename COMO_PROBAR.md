# Cómo probar el NIDS-ML — guía de la rama `Anderson`

Esta guía explica cómo descargar y ejecutar **la versión actual de la rama
`Anderson`**: un NIDS (sistema de detección de intrusiones) con un modelo
**Random Forest** que clasifica tráfico en tiempo real, un atacante que lanza
**tres ataques reales** o **tráfico normal** dentro de Docker, veredictos
🔴 **ATAQUE** / 🟢 **NORMAL** en la terminal y un **panel web** que se actualiza
solo.

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
| `attacker` | Un contenedor Kali con `hping3`, `nmap` y `curl` | Lanza tres familias de ataque o tráfico HTTP legítimo contra `victim`. |
| `nids` | El detector, escrito en Python con Scapy y scikit-learn | Captura el tráfico real, lo agrupa en flujos y los clasifica con un Random Forest. Persiste ataques **y** tráfico normal. |
| `dashboard` | Un panel Streamlit | Muestra los flujos en el navegador, con veredicto 🔴/🟢, y se refresca cada 2 segundos. |
| `demo-menu.ps1` | Un menú en PowerShell | Levanta todo, lanza tráfico normal o ataques (solos o combinados) y muestra el resumen. |

Cuando lo corras vas a ver, en este orden:

1. El menú verifica Docker y levanta `victim`, `nids` y `dashboard`.
2. Elegís tráfico normal, un ataque, los tres, o un ataque combinado con
   tráfico normal.
3. El atacante ejecuta lo elegido y muestra su progreso en la terminal.
4. El detector imprime líneas `ATAQUE score=...` o `NORMAL score=...` y escribe
   **todos** los flujos en `output/alertas.jsonl`.
5. El panel web muestra los flujos en una tabla con veredicto 🔴 **ATAQUE** o
   🟢 **NORMAL**, sin recargar la página.

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
   y pueda encadenar varias corridas. También quita `NIDS_THRESHOLD` al
   arrancar; lo vuelve a aplicar en cada corrida según incluya tráfico normal
   o no.
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
  Verificá Docker, levantá el detector y lanzá tráfico normal o ataques.
[..] Asegurando victim y nids (detector indefinido)...
[OK] victim y nids arriba (NIDS_DURATION=0).
[..] Levantando el dashboard...
[OK] Dashboard listo.
    Abrí el panel en: http://localhost:8501

================================================================
  NIDS-ML · Menú de demostración
================================================================
  Dashboard: http://localhost:8501

  1) Solo tráfico normal
  2) SYN flood                 (perfil neptune: SYNs sin respuesta)
  3) Escaneo de puertos        (perfil nmap)
  4) Inundación HTTP           (perfil satan)
  5) Los tres ataques
  6) Ataque + tráfico normal   (pregunta cuál ataque: 1/2/3/all)
  7) Salir

  Nota: las corridas con tráfico normal usan umbral de demo 0.30
        (el artefacto usa 0.05; el benigno medido puntúa ~0.13-0.16).

  Elegí una opción [1-7]:
```

---

## Usar el menú

| Opción | Qué corre | Perfil de NSL-KDD | Qué hace |
|---|---|---|---|
| `1` | Solo tráfico normal | tráfico legítimo | 30 GET HTTP a `victim:80`, uno cada 0.5 s, sin ningún ataque. Usa umbral de demo 0.30. |
| `2` | SYN flood | `neptune` | 400 SYN a `victim:80`, con orígenes falsos y sin respuesta. |
| `3` | Escaneo de puertos | `nmap` | Escaneo SYN de 300 puertos desde un mismo origen. |
| `4` | Inundación HTTP | `satan` | 60 peticiones POST con carga, esperando respuesta. |
| `5` | Los tres ataques | `neptune + nmap + satan` | Ejecuta los tres, espaciados en el tiempo. |
| `6` | Ataque + tráfico normal | el del ataque elegido | Pregunta cuál ataque (`1`=SYN flood, `2`=escaneo, `3`=HTTP flood, `all`=los tres) y lo corre con tráfico normal en paralelo. Usa umbral de demo 0.30. |
| `7` | Salir | — | Sale del menú y pregunta si querés apagar la demo. |

> ℹ️ **Cuidado con la numeración.** La opción del **menú** no coincide con el
> id de ataque de `-Attack`: menú `2` = `-Attack 1` (SYN flood), menú `3` =
> `-Attack 2` (escaneo), menú `4` = `-Attack 3` (HTTP flood) y menú `5` =
> `-Attack all`. La opción `6` equivale a `-Attack <id> -WithNormal`.

Al elegir una opción vas a ver el **progreso del atacante en vivo** en esa misma
terminal. Por ejemplo, con la opción `5` (los tres ataques):

```text
================================================================
  CORRIDA: Los tres ataques
================================================================
  Perfil NSL-KDD : neptune + nmap + satan
  Qué hace       : SYN flood, escaneo de puertos y flood HTTP
  Umbral         : 0.05 (artefacto)

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

> ℹ️ Con un solo ataque (menú `2`, `3` o `4`) no aparece el contador `[x/3]` y
> el cierre dice `Ataque completado.` en singular. El contador aparece con el
> menú `5` (o con `-Attack all`). En las corridas **mixtas** el cierre dice
> `Ataque(s) y tráfico normal completados.`; en las de solo tráfico normal dice
> `Tráfico normal completado.`

### Dónde ver las líneas `ATAQUE` y `NORMAL`

El menú corre el atacante en primer plano, pero **el detector corre en segundo
plano**. Por eso las líneas crudas del NIDS no salen en la terminal del menú:
salen en los logs del contenedor y, sobre todo, en el panel web.

Si querés proyectarlas en otra terminal:

```powershell
docker compose logs -f nids
```

Vas a ver, mientras corre la demo:

```text
nids-detector  | ATAQUE score=0.797 tcp/http flag=S0 src_bytes=0 serror=1.00
nids-detector  | ATAQUE score=0.660 tcp/http flag=SF src_bytes=0 serror=0.00
nids-detector  | NORMAL score=0.141 tcp/http flag=SF src_bytes=0 serror=0.00
```

Los valores de `score`, `flag` y bytes varían según el flujo. La señal de que
todo funciona es que aparezcan líneas que empiecen con `ATAQUE` (rojo) o
`NORMAL` (verde). Ya **no** se imprimen líneas con la palabra `ALERTA`: el
detector ahora persiste y rotula ambos veredictos.

### Resumen al terminar cada corrida

El menú detiene el NIDS unos segundos para que vuelque los flujos pendientes
(por ejemplo, los SYN que nunca recibieron respuesta) y después lo vuelve a
levantar. Por eso vas a ver estas líneas y luego el resumen:

```text
[..] Volcando alertas pendientes (deteniendo nids de forma limpia)...
[..] Reiniciando el detector para el proximo ataque...

  RESUMEN
  ------------------------------------------------------
    Corrida                  : Los tres ataques
    Alertas nuevas (ataques) : 44
    Flujos normales nuevos   : 3
    Duración aprox.          : 19,7 s

  RESULTADOS
  ------------------------------------------------------
    Últimos 10 evento(s) nuevos:
    hora       veredicto   score  detalle
    12:23:51   ATAQUE      0,797  tcp/http flag=S0 count=1
    12:23:51   ATAQUE      0,797  tcp/http flag=S0 count=1
    12:23:53   NORMAL      0,141  tcp/http flag=SF count=6
    ...

    Detalle completo: http://localhost:8501
```

Los números de `Alertas nuevas (ataques)`, `Flujos normales nuevos` y
`Duración` **cambian en cada corrida**:

- En una corrida de **solo ataque**, lo importante es que
  `Alertas nuevas (ataques)` sea mayor que cero.
- En una corrida de **solo tráfico normal**, lo importante es que
  `Flujos normales nuevos` sea mayor que cero (del orden de 24–30).
- En una corrida **mixta**, ambos contadores deberían ser mayores que cero.

Si no hay eventos nuevos, el menú muestra
"No se registraron eventos nuevos." y una pista para revisar.

La columna `detalle` del menú usa el formato
`protocolo/servicio flag=... count=...`. El detalle completo, con bytes y tasa
de error, está en el panel.

### Tráfico normal y umbral de demo 0.30

La opción `1` (y el tráfico paralelo de la opción `6`) hace que el contenedor
del atacante envíe **30 peticiones HTTP GET** a `http://victim/`, espaciadas
0.5 s (unos 15 s en total). No hay ningún ataque: es tráfico de fondo legítimo
contra el servidor.

Sale desde el contenedor `attacker`, que comparte el espacio de red del NIDS
(`network_mode: service:nids`). Por eso el detector lo ve en `eth0` como
cualquier otro flujo: no hace falta un contenedor extra ni publicar puertos.

Qué esperar en el panel y en los logs:

- Alrededor de **24 a 30 filas 🟢 NORMAL**, `protocolo=tcp`, `servicio=http`,
  `flag=SF` (conexión abierta y cerrada correctamente) y `score` entre
  **0.13 y 0.16**. En los logs del NIDS son líneas
  `NORMAL score=0.1xx ...`.
- Ninguna fila de ataque, salvo la excepción conocida de la nota siguiente.
- La métrica **"Tráfico normal"** del panel sube en esa misma cantidad.

> ⚠️ **Falso positivo conocido (1 flujo).** En una corrida de solo tráfico
> normal puede aparecer **una** fila 🔴 ATAQUE con `flag=S0` y `score≈0.74`.
> Corresponde al SYN inicial de una conexión legítima cuya respuesta cayó fuera
> de la ventana de 2 s del detector: el flujo queda como "SYN sin respuesta",
> que es el patrón de un SYN flood. Es una limitación conocida de la ventana,
> no un fallo de la demo. Si aparece exactamente una, el resultado sigue siendo
> correcto.

#### Por qué se usa 0.30 y no el 0.05 del artefacto

El modelo se entrenó con umbral **0.05**, pensado para no perder ataques. Con
ese umbral, el tráfico benigno de esta demo (que puntúa 0.13–0.16) también
supera el corte y aparecería todo como ataque. Para poder mostrar tráfico
normal de forma creíble, las corridas que incluyen tráfico benigno usan
`NIDS_THRESHOLD=0.30`:

| Corrida | Umbral | Efecto |
|---|---|---|
| Solo ataques (menú `2`–`5`, `-Attack 1/2/3/all`) | **0.05** (artefacto) | Máxima sensibilidad; el benigno residual también se marca. |
| Con tráfico normal (menú `1` y `6`, `-Attack normal`, `-WithNormal`) | **0.30** (demo) | El benigno (0.13–0.16) queda como 🟢 NORMAL; los ataques de la demo (0.53–0.80) siguen siendo 🔴 ATAQUE. |

Los ataques medidos en esta demo puntúan:

| Flujo | Score aproximado |
|---|---|
| Tráfico normal HTTP | 0.13 – 0.16 |
| Escaneo de puertos | 0.53 – 0.57 |
| Inundación HTTP | 0.66 |
| SYN flood | 0.80 |

**El trade-off, sin maquillaje:** subir el umbral a 0.30 también descarta
flujos de ataque que puntúen por debajo de ese valor. En la inundación HTTP
algunas conexiones individuales son sutiles y pueden quedar como normales; lo
que se sigue detectando es el grueso del ataque. Es un ajuste **explícito de
demostración**, no el umbral con el que se reportan las métricas del modelo.

El menú aplica el umbral solo, recreando el contenedor `nids`:

- al elegir una corrida con tráfico normal, imprime
  `[OK] NIDS con umbral 0.30.`;
- al volver a una corrida de solo ataque, imprime
  `[OK] NIDS con umbral 0.05.` y elimina el override.

El NIDS publica el umbral efectivo en `output/nids_runtime.json`, y el panel lo
muestra en un caption debajo del estado del detector:

```text
⚠️ Umbral de demo activo: 0.30 (el artefacto usa 0.05). Es un ajuste explícito
de la demo: con un umbral más alto se pierden ataques sutiles; los ataques de
esta demo puntúan ~0.53-0.80, así que se siguen detectando.
```

En una corrida de solo ataque el caption dice
`Umbral del artefacto en uso: 0.05 (sin override de demo).`

### Preguntas del menú

Después de cada corrida:

```text
  ¿Volver al menú? (s/n)
```

- **`s`** → vuelve al menú para lanzar otra corrida.
- **`n`** → sale del menú y pasa a la pregunta final.

La pregunta final es:

```text
  ¿Apagar la demo? (s/n)
```

- **`s`** → ejecuta `docker compose down` y apaga todo.
- **`n`** → deja la demo corriendo y muestra el link del panel.

La opción `7` del menú también llega a esta pregunta final.

> 💡 Si apretás **Ctrl+C** durante la demo, el script avisa
> "Demo interrumpida (Ctrl+C)." y sale, pero **los contenedores siguen
> corriendo**. En ese caso apagalos a mano con `docker compose down`.

Ni la opción `7` ni responder `n` a la pregunta de apagado borra los eventos:
quedan en `output/alertas.jsonl` y el panel los sigue mostrando mientras esté
arriba.

---

## Modo rápido sin menú

Si querés lanzar una corrida y salir, sin menú ni preguntas:

```powershell
powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1 -Attack normal
```

`-Attack` acepta estos valores:

| Valor | Qué corre | Umbral |
|---|---|---|
| `normal` | Solo tráfico normal: 30 GET HTTP a `victim`. | 0.30 (demo) |
| `1` | SYN flood | 0.05 (artefacto) |
| `2` | Escaneo de puertos | 0.05 (artefacto) |
| `3` | Inundación HTTP | 0.05 (artefacto) |
| `all` | Los tres ataques | 0.05 (artefacto) |

`-WithNormal` agrega tráfico normal **en paralelo** a un ataque. Solo tiene
efecto junto con `-Attack 1`, `2`, `3` o `all`; en ese caso el umbral pasa a
0.30. Ejemplos:

```powershell
# Solo tráfico normal (filas 🟢 NORMAL)
powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1 -Attack normal

# Solo ataques (umbral del artefacto)
powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1 -Attack 1
powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1 -Attack all

# Ataque + tráfico normal en paralelo (umbral de demo 0.30)
powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1 -Attack all -WithNormal
powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1 -Attack 3 -WithNormal
```

Qué hace este modo:

- Verifica Docker y levanta **solo `victim` y `nids`** (no levanta el dashboard).
- Ajusta `NIDS_THRESHOLD` según corresponda (0.30 si hay tráfico normal; sin
  override si es solo ataque).
- Lanza la corrida elegida y muestra su progreso.
- Detiene el NIDS para volcar los flujos pendientes, lo vuelve a levantar y
  muestra el resumen con ataques y normales por separado.
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
el estado del detector, el **caption del umbral activo**, las métricas del
modelo (si existen), la tabla de eventos y las leyendas de veredicto y flags.

Las cuatro tarjetas son:

| Tarjeta | Qué significa |
|---|---|
| **Modelo entrenado** | `sí` si el artefacto del modelo está dentro de la imagen. |
| **Eventos totales** | Cantidad de eventos guardados en `output/alertas.jsonl` (ataques + normales, incluye corridas anteriores). |
| **Detectados como ataque** | Cuántos de esos eventos tienen veredicto 🔴 `ATAQUE`. |
| **Tráfico normal** | Cuántos tienen veredicto 🟢 `NORMAL`. |

> ℹ️ El detector ahora **persiste todos los flujos**, no solo los ataques. Por
> eso `Eventos totales` = `Detectados como ataque` + `Tráfico normal`, y una
> corrida con tráfico benigno hace subir la métrica "Tráfico normal". Si ves
> `Tráfico normal = 0` después de una corrida normal, revisá que esa corrida
> haya usado el menú `1` o `-Attack normal`.

Debajo aparece el estado del detector:

- **🟢 Capturando en vivo (último evento hace N s)** cuando el último evento
  tiene menos de 15 segundos.
- **⚪ Detector detenido o sin captura reciente** cuando no hay eventos o el
  último es más viejo que 15 segundos. Es una heurística, no un chequeo de
  salud del contenedor: después de una corrida es normal que pase a ⚪.

Justo debajo del estado, el panel muestra un **caption con el umbral efectivo**
que el NIDS publica en `output/nids_runtime.json`:

- En corridas con tráfico normal:
  `⚠️ Umbral de demo activo: 0.30 (el artefacto usa 0.05)...`
- En corridas de solo ataque:
  `Umbral del artefacto en uso: 0.05 (sin override de demo).`
- Si el archivo todavía no existe (el NIDS no arrancó), un texto general que
  explica que el artefacto usa 0.05 y la demo 0.30.

Ese caption es la fuente de verdad para saber si el panel está mostrando una
corrida de demo con umbral relajado o una corrida con el umbral del artefacto.
El detalle conceptual está en
[Tráfico normal y umbral de demo 0.30](#tráfico-normal-y-umbral-de-demo-030).

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
hace falta recargar ni apretar F5: durante una corrida vas a ver las filas
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

### Tabla de eventos

Muestra los **200 eventos más recientes**, primero los más nuevos. Columnas:

| Columna | Qué es |
|---|---|
| `hora` | Hora local del evento (`HH:MM:SS`). |
| `veredicto` | 🔴 `ATAQUE` o 🟢 `NORMAL`, según el umbral efectivo. |
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
`serror=1.00`. El tráfico normal HTTP deja filas con `flag=SF`, `score` 0.13–
0.16 y `serror=0.00`.

Si ves **"Sin alertas todavía"**, todavía no corrió ninguna captura. Lanzá una
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

El menú es el camino recomendado porque encadena corridas y cuenta los eventos
nuevos. Si preferís hacerlo a mano, estos son los comandos equivalentes.

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

### Corrida manual de tráfico normal o mixta

El compose por defecto lanza los tres ataques con el umbral del artefacto
(0.05). Para hacer a mano una corrida de **solo tráfico normal**, con el umbral
de demo:

```powershell
$env:NIDS_THRESHOLD = "0.30"
docker compose up -d victim nids
docker compose run --rm -e ATTACK=normal -e NIDS_WARMUP=0 attacker
docker compose stop nids     # vuelca los flujos que quedaron abiertos
```

Para un **ataque + tráfico normal en paralelo**:

```powershell
$env:NIDS_THRESHOLD = "0.30"
docker compose up -d victim nids
docker compose run --rm -e ATTACK=all -e TRAFFIC=normal -e NIDS_WARMUP=0 attacker
docker compose stop nids
```

Para volver al umbral del artefacto (0.05) en la próxima corrida:

```powershell
Remove-Item Env:NIDS_THRESHOLD -ErrorAction SilentlyContinue
docker compose up -d nids
```

> ⚠️ `TRAFFIC` no está declarado como variable de entorno del servicio
> `attacker` en `docker-compose.yml`: por eso en el flujo manual hay que
> pasarlo con `docker compose run -e TRAFFIC=normal`. El menú lo hace solo.

Para cortar el flujo manual: **Ctrl+C** en la Terminal A y después
`docker compose down`.

---

## Apagar todo

La forma limpia:

```powershell
docker compose down
```

Eso detiene y elimina los contenedores y la red de la demo. **No borra** los
eventos de `output/alertas.jsonl` ni las imágenes descargadas, así que la
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
| `Alertas nuevas (ataques): 0` / no aparece ninguna línea `ATAQUE` | El ataque no llegó a tiempo o el detector se reinició | Probá `-Attack 1` de nuevo. Revisá `docker compose logs nids`. Si sigue, `docker compose down` y volvé a empezar. |
| `Flujos normales nuevos: 0` en una corrida normal | El tráfico normal no salió o el NIDS no estaba capturando | Revisá `docker compose logs nids`; debe haber líneas `NORMAL score=0.1xx`. Probá `-Attack normal` de nuevo. |
| En solo tráfico normal aparece 1 fila 🔴 ATAQUE con `flag=S0` y `score≈0.74` | Falso positivo conocido: SYN inicial cuya respuesta cayó fuera de la ventana de 2 s | Es esperable. Si aparece **una sola**, la corrida está bien. Está documentado en [Tráfico normal y umbral de demo 0.30](#tráfico-normal-y-umbral-de-demo-030). |
| El panel dice `Umbral de demo activo: 0.30` cuando querías solo ataques | La última corrida fue normal o mixta; el contenedor quedó con `NIDS_THRESHOLD=0.30` | Lanzá una corrida de solo ataque (menú `2`–`5` o `-Attack 1/2/3/all`): el menú vuelve a 0.05. A mano: `Remove-Item Env:NIDS_THRESHOLD` y `docker compose up -d nids`. |
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

El archivo de eventos es **append-only**: cada corrida agrega líneas y nunca se
reescribe. Ahora se persisten **todos los flujos** (ataques y normales), así
que una corrida benigna también agrega decenas de líneas. Por eso:

- El menú cuenta **solo los eventos nuevos** de cada corrida, separados en
  `Alertas nuevas (ataques)` y `Flujos normales nuevos`.
- El panel muestra **todo el histórico** en `Eventos totales`, y separa
  `Detectados como ataque` de `Tráfico normal`.
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
    ├── nids       detector: captura en eth0, clasifica y escribe eventos
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
  imprime `modelo: random_forest   umbral: 0.05 (artefacto)` (o
  `0.30 (demo, override NIDS_THRESHOLD)`), captura con Scapy en `eth0`, agrupa
  paquetes en ventanas de **2 segundos** (y una ventana de host de 100
  segundos), arma el vector con las 23 features soportadas por flujo (20
  numéricas + 3 categóricas) y clasifica. **Persiste todos los flujos**, con
  etiqueta `ataque` o `normal`, imprime `ATAQUE ...` o `NORMAL ...` y agrega una
  línea JSON a `output/alertas.jsonl`. También escribe
  `output/nids_runtime.json` con el umbral efectivo.
- **`attacker`**: corre `docker/attack.sh`. Lanza 400 SYN (SYN flood), un
  escaneo SYN de 300 puertos, 60 peticiones HTTP y, cuando se lo pide,
  30 GET HTTP de tráfico normal (solos o en paralelo al ataque). Cada ataque
  tiene `timeout`: si una herramienta se traba, el script sigue y la demo no se
  cuelga.
- **`dashboard`**: Streamlit dentro de la misma imagen del NIDS. Lee el JSONL
  cada 2 segundos y dibuja las métricas, el caption del umbral y la tabla.
  **Solo lee**, no escribe.
- **`demo-menu.ps1`**: orquestador en PowerShell. No usa Python del host:
  ejecuta `docker compose`, ajusta `NIDS_THRESHOLD`, cuenta eventos del JSONL y
  muestra el resumen separado en ataques y normales.

### El modelo y los umbrales (0.05 del artefacto, 0.30 de demo)

- **Random Forest** de 300 árboles, con `class_weight="balanced"`.
- Usa **23 de las 41 features** de NSL-KDD (20 numéricas + 3 categóricas). Las
  otras 18 no se pueden derivar del tráfico capturado en vivo; quedan en 0 y
  están documentadas. No se inventan features.
- **Umbral del artefacto: 0.05**, no el 0.5 que usa scikit-learn por defecto.
  Es una decisión deliberada: en un NIDS, una alerta de más se revisa; un ataque
  perdido no se recupera. Con 0.5 el recall bajaba a 0.64 (se perdía un tercio
  de los ataques).
- **Umbral de demo: 0.30**, aplicado **solo** cuando la corrida incluye
  tráfico normal (`NIDS_THRESHOLD=0.30`). No reemplaza al del artefacto: es un
  override explícito para que el benigno (0.13–0.16) no se marque como ataque.
  El trade-off es que también se pierden flujos sutiles de ataque (parte del
  HTTP flood).
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
2. Levantar `victim` y `nids` y ejecutar, como mínimo, **una corrida de solo
   tráfico normal** y **una de ataques**. Opcional pero recomendado: una corrida
   mixta (ataque + tráfico normal).
3. Confirmar que el NIDS emite veredictos `ATAQUE` y `NORMAL`, y que persiste
   ambos en `output/alertas.jsonl` (`"label":"ataque"` / `"label":"normal"`).
4. Confirmar que el panel responde HTTP 200 en `http://localhost:8501`, que la
   tabla muestra 🔴/🟢 y que el caption refleja el umbral efectivo.
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

**Modo recomendado para un agente (no interactivo).** Elegí el comando según lo
que quieras demostrar:

| Objetivo | Comando |
|---|---|
| Mostrar solo tráfico normal (🟢) | `powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1 -Attack normal` |
| Mostrar solo ataques (🔴) | `powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1 -Attack all` |
| Mostrar ambos en la misma corrida | `powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1 -Attack all -WithNormal` |
| Un ataque puntual + normal | `powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1 -Attack 3 -WithNormal` |

Secuencia completa sugerida (tres corridas, sin intervención):

```powershell
powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1 -Attack normal
powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1 -Attack all
powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1 -Attack all -WithNormal
```

- Cada comando termina solo y no pregunta nada.
- No abren el dashboard (solo levantan `victim` y `nids`).
- `-Attack normal` tarda ~20–30 s; `all` ~20–90 s; la corrida mixta suma unos
  15 s de tráfico normal en paralelo.
- La primera vez puede tardar 5–15 minutos más por la descarga (~1.8 GB).
- `-Attack normal` deja `NIDS_THRESHOLD=0.30`; `-Attack 1/2/3/all` sin
  `-WithNormal` vuelve al 0.05 del artefacto automáticamente.

Ataques individuales (umbral del artefacto, sin tráfico normal):

```powershell
powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1 -Attack 1   # SYN flood
powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1 -Attack 2   # escaneo
powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1 -Attack 3   # HTTP flood
```

**Modo interactivo (solo si hay un humano presente):**

```powershell
powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1
```

Ese modo espera entrada por teclado (`1`–`7`, `s`/`n`). **No lo uses en
automatización**: se quedaría esperando. La opción `6` además pregunta cuál
ataque (`1`, `2`, `3` o `all`).

### 3. Salidas esperadas

#### 3.1 Solo tráfico normal (`-Attack normal`)

La salida debe contener estos hitos:

```text
[..] Modo automático: una corrida (normal), sin menú.
[..] Asegurando victim y nids (detector indefinido)...
[OK] victim y nids arriba (NIDS_DURATION=0).

================================================================
  CORRIDA: Solo tráfico normal
================================================================
  Perfil NSL-KDD : tráfico legítimo
  Qué hace       : 30 requests HTTP GET a la víctima (sin ataque)
  Umbral         : 0.30 (demo, NIDS_THRESHOLD)
                   el artefacto usa 0.05; el benigno medido puntúa ~0.13-0.16
  Tráfico normal : sí, sin ataques
[OK] NIDS con umbral 0.30.

==============================================
 ATACANTE - objetivo: victim
 Ataque(s): normal
==============================================
NIDS_WARMUP=0: arrancando sin espera inicial.

>>> Tráfico normal: 30 requests HTTP GET a http://victim/
    Tráfico normal terminado (30 requests)

==============================================
 Tráfico normal completado. Revisa la salida del NIDS.
==============================================
```

Después del volcado, el resumen debe mostrar:

```text
  RESUMEN
  ------------------------------------------------------
    Corrida                  : Solo tráfico normal
    Alertas nuevas (ataques) : 1
    Flujos normales nuevos   : 25
    Duración aprox.          : 24,3 s

  RESULTADOS
  ------------------------------------------------------
    Últimos 10 evento(s) nuevos:
    hora       veredicto   score  detalle
    12:40:02   NORMAL      0,133  tcp/http flag=SF count=6
    12:40:03   ATAQUE      0,741  tcp/http flag=S0 count=1
    ...

    Detalle completo: http://localhost:8501
```

Qué es aceptable:

- `Flujos normales nuevos` entre **24 y 30** (a veces 30 exactos).
- `Alertas nuevas (ataques)` en **0 o 1**. Si hay exactamente **1**, debe ser
  la fila `flag=S0` con score ≈0.74 descrita en
  [Tráfico normal y umbral de demo 0.30](#tráfico-normal-y-umbral-de-demo-030):
  es el falso positivo conocido. **Más de una alerta de ataque en una corrida
  benigna es un fallo** que hay que reportar.

#### 3.2 Solo ataques (`-Attack all`)

```text
[..] Modo automático: una corrida (all), sin menú.
[..] Asegurando victim y nids (detector indefinido)...
[OK] victim y nids arriba (NIDS_DURATION=0).

================================================================
  CORRIDA: Los tres ataques
================================================================
  Perfil NSL-KDD : neptune + nmap + satan
  Qué hace       : SYN flood, escaneo de puertos y flood HTTP
  Umbral         : 0.05 (artefacto)

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

Resumen esperado:

```text
  RESUMEN
  ------------------------------------------------------
    Corrida                  : Los tres ataques
    Alertas nuevas (ataques) : 44
    Flujos normales nuevos   : 2
    Duración aprox.          : 19,7 s
```

#### 3.3 Ataque + tráfico normal (`-Attack all -WithNormal`)

```text
[..] Modo automático: ataque + tráfico normal (all), sin menú.
[..] Asegurando victim y nids (detector indefinido)...
[OK] victim y nids arriba (NIDS_DURATION=0).

================================================================
  CORRIDA: Los tres ataques
================================================================
  ...
  Umbral         : 0.30 (demo, NIDS_THRESHOLD)
                   el artefacto usa 0.05; el benigno medido puntúa ~0.13-0.16
  Tráfico normal : sí, en paralelo al ataque
[OK] NIDS con umbral 0.30.

==============================================
 ATACANTE - objetivo: victim
 Ataque(s): all
 Tráfico normal: en paralelo
==============================================
...
 Ataque(s) y tráfico normal completados. Revisa la salida del NIDS.
==============================================
```

En el resumen, **ambos** contadores deben ser mayores que cero
(`Alertas nuevas (ataques)` y `Flujos normales nuevos`). El tráfico normal
corre en segundo plano y el script espera a que termine antes de cerrar.

#### 3.4 Verificación de los veredictos

Las líneas crudas del detector están en el log de `nids`, no en la terminal del
menú. Verificalas así:

```powershell
docker compose logs nids | Select-String 'ATAQUE' | Select-Object -Last 10
docker compose logs nids | Select-String 'NORMAL' | Select-Object -Last 10
```

Debe haber líneas con esta forma (score y flag varían):

```text
nids-detector  | ATAQUE score=0.797 tcp/http flag=S0 src_bytes=0 serror=1.00
nids-detector  | NORMAL score=0.141 tcp/http flag=SF src_bytes=0 serror=0.00
```

En una corrida de solo tráfico normal, el log debe tener muchas líneas
`NORMAL score=0.1xx` y como máximo una `ATAQUE ... flag=S0`. En una corrida de
solo ataque, debe tener líneas `ATAQUE` y prácticamente ninguna `NORMAL`.

Verificación directa del store (conteo por etiqueta):

```powershell
(Select-String -Path .\output\alertas.jsonl -Pattern '"label":"normal"').Count
(Select-String -Path .\output\alertas.jsonl -Pattern '"label":"ataque"').Count
```

Verificación del umbral efectivo que muestra el panel:

```powershell
Get-Content .\output\nids_runtime.json
```

Ejemplo con umbral de demo:

```json
{"threshold":0.3,"artifact_threshold":0.05,"demo":true,"updated_at":"..."}
```

Ejemplo con umbral del artefacto:

```json
{"threshold":0.05,"artifact_threshold":0.05,"demo":false,"updated_at":"..."}
```

La tabla de cierre del detector también queda en ese log:

```powershell
docker compose logs nids | Select-String 'Resumen en vivo|paquetes capturados|flujos analizados|alertas emitidas|tráfico normal|tasa de alerta'
```

Ejemplo de lo que imprime (los valores cambian):

```text
nids-detector  |       Resumen en vivo (24s)
nids-detector  | ┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┓
nids-detector  | ┃ metrica             ┃ valor   ┃
nids-detector  | ┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━┩
nids-detector  | │ paquetes capturados │ 412     │
nids-detector  | │ flujos analizados   │ 26      │
nids-detector  | │ alertas emitidas    │ 1       │
nids-detector  | │ tráfico normal      │ 25      │
nids-detector  | │ tasa de alerta      │ 3.85%   │
nids-detector  | └─────────────────────┴─────────┘
nids-detector  | Eventos persistidos en output/alertas.jsonl
```

> ℹ️ Esta tabla aparece cuando el proceso del NIDS termina de forma limpia. En el
> menú ocurre después de cada corrida (el script lo detiene para volcar); en el
> flujo manual ocurre a los 90 segundos o al hacer `docker compose stop nids`.

### 4. Verificación del panel

El modo `-Attack` **no levanta el dashboard**. Para verificarlo, levantalo y
esperá hasta 60 segundos:

```powershell
docker compose up -d dashboard

$r = Invoke-WebRequest -Uri http://localhost:8501 -UseBasicParsing -TimeoutSec 20
$r.StatusCode
```

Resultado esperado: **`200`**.

`Invoke-WebRequest` devuelve el shell HTML de Streamlit, no la tabla renderizada,
así que los veredictos y el caption se verifican con el JSONL y
`output/nids_runtime.json` (paso 3.4) o abriendo el panel. En el navegador:

- La tabla debe mostrar filas 🔴 **ATAQUE** y/o 🟢 **NORMAL** según la corrida.
- La métrica **"Tráfico normal"** debe ser mayor que 0 tras `-Attack normal`.
- Debajo del estado debe aparecer el caption del umbral:
  `⚠️ Umbral de demo activo: 0.30...` o
  `Umbral del artefacto en uso: 0.05...`.

> ⚠️ Revisá las líneas `ATAQUE`/`NORMAL` **antes** de este paso. Si Compose
> recrea `nids` (por ejemplo, porque `NIDS_DURATION` o `NIDS_THRESHOLD` cambian
> al ejecutar el comando en una shell nueva), el contenedor nuevo arranca con
> logs vacíos y las líneas de la corrida anterior ya no aparecen en
> `docker compose logs nids`. El panel no se ve afectado porque lee el JSONL,
> pero el detector puede quedar con la duración por defecto de 90 s.

Si `Invoke-WebRequest` falla, revisá en este orden:

```powershell
docker compose ps
docker compose logs --tail 80 dashboard
Get-NetTCPConnection -LocalPort 8501 -ErrorAction SilentlyContinue
```

### 5. Criterios de éxito

La prueba se considera exitosa si se cumplen **todos** estos puntos:

**Corrida de solo tráfico normal (`-Attack normal`)**

- [ ] Termina sin errores de PowerShell.
- [ ] La salida contiene `Tráfico normal completado.`
- [ ] La salida contiene `Flujos normales nuevos   : N` con `N` entre 24 y 30.
- [ ] La salida contiene `Umbral         : 0.30 (demo, NIDS_THRESHOLD)`.
- [ ] `Alertas nuevas (ataques)` es `0` o `1`; si es `1`, el flujo es `flag=S0`
      con score ≈0.74 (falso positivo conocido).
- [ ] `output/nids_runtime.json` tiene `"threshold":0.3` y `"demo":true`.

**Corrida de solo ataques (`-Attack all`)**

- [ ] La salida contiene `[1/3]`, `[2/3]`, `[3/3]` y `Ataques completados.`
- [ ] La salida contiene `Alertas nuevas (ataques) : N` con `N > 0`.
- [ ] La salida contiene `Umbral         : 0.05 (artefacto)`.
- [ ] `output/nids_runtime.json` tiene `"threshold":0.05` y `"demo":false`.

**Corrida mixta (`-Attack all -WithNormal`)**

- [ ] La salida contiene `Ataque(s) y tráfico normal completados.`
- [ ] `Alertas nuevas (ataques)` **y** `Flujos normales nuevos` son mayores
      que cero.

**Comunes**

- [ ] Tras la secuencia completa, `docker compose logs nids` contiene al menos
      una línea `ATAQUE score=` y una `NORMAL score=` (la corrida mixta produce
      ambas).
- [ ] `Select-String` sobre `output/alertas.jsonl` encuentra
      `"label":"ataque"` y `"label":"normal"`.
- [ ] El log del NIDS contiene `Resumen en vivo` (o al menos
      `alertas emitidas` y `tráfico normal`).
- [ ] `Invoke-WebRequest http://localhost:8501` devuelve `200`.
- [ ] `docker compose ps` muestra `nids-victim` corriendo y, si la corrida
      acaba de terminar, también `nids-detector`.

> ⚠️ El script devuelve código de salida `0` aunque el atacante haya terminado
> con error (solo imprime una advertencia `[!] El atacante terminó con código
> N.`). Por eso **no alcanza con mirar el exit code**: verificá también las
> líneas y los conteos.

### 6. Si falla, revisar en este orden

1. **Carpeta y archivos**: `Test-Path .\docker-compose.yml` y
   `Test-Path .\demo-menu.ps1` deben dar `True`.
2. **Rama**: `git branch --show-current` debe dar `Anderson`.
3. **Docker**: `docker info --format 'Server={{.ServerVersion}}'` debe
   responder. Si no, abrir Docker Desktop y esperar.
4. **Contenedores**: `docker compose ps -a` para ver estados y reinicios.
5. **Log del detector**: `docker compose logs --tail 80 nids`. Buscar
   `modelo:`, `umbral:`, `Capturando en eth0`, `ATAQUE`, `NORMAL` y
   `Resumen en vivo`.
6. **Umbral efectivo**: `Get-Content .\output\nids_runtime.json`. Si dice 0.30
   cuando esperabas ataques, lanzá una corrida de solo ataque para volver a
   0.05.
7. **Log del panel**: `docker compose logs --tail 80 dashboard`. Buscar errores
   de puerto o de arranque de Streamlit.
8. **Puerto 8501**: `Get-NetTCPConnection -LocalPort 8501 -ErrorAction SilentlyContinue`.
9. **Reinicio limpio**: `docker compose down`, esperar 5 segundos y repetir.
10. Si sigue fallando, reportar el comando exacto, la salida y los logs. **No
    parchear el código ni el compose para que "pase".**

### 7. Reglas y restricciones

- Trabajar **solo** en la rama `Anderson`. No hacer checkout, merge ni push a
  `main` (ni local ni remota).
- **Nunca** usar `git push --force` ni reescribir historia.
- **No borrar** `output/alertas.jsonl` sin autorización explícita: es
  append-only y puede contener evidencia de corridas anteriores.
- **No modificar** `demo-menu.ps1`, `docker-compose.yml`, `docker/attack.sh`,
  `dashboard.py` ni el código para "arreglar" la demo. Si algo falla, reportar.
- **No cambiar el umbral a mano** para forzar un resultado: el menú ya aplica
  0.30 en corridas con tráfico normal y 0.05 en las de solo ataque.
- No atacar hosts externos: `attack.sh` apunta a `victim` dentro de `nidsnet`.
  No cambiar el objetivo ni ejecutar las herramientas de Kali contra tu red.
- No ejecutar `docker system prune`, `docker compose down -v` ni borrar
  imágenes: son destructivos y no forman parte de la prueba.
- No publicar puertos nuevos. El único puerto necesario es `8501`.
- Si hay que publicar cambios, hacerlo solo con `git push origin Anderson`.

### 8. Nota sobre el contador de eventos

`output/alertas.jsonl` es **append-only** y acumula entre corridas. Ahora
contiene ataques **y** flujos normales:

- El menú informa `Alertas nuevas (ataques)` y `Flujos normales nuevos`
  comparando el archivo antes y después de cada corrida.
- El panel informa `Eventos totales` con **todo** el histórico y separa
  `Detectados como ataque` de `Tráfico normal`.
- Una corrida benigna agrega del orden de 24–30 líneas `"label":"normal"`, así
  que el archivo crece más rápido que antes.
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
| Ver solo tráfico normal | `powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1 -Attack normal` |
| Lanzar un ataque suelto | `powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1 -Attack 1` |
| Lanzar los tres | `powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1 -Attack all` |
| Ataque + tráfico normal | `powershell -ExecutionPolicy Bypass -File .\demo-menu.ps1 -Attack all -WithNormal` |
| Abrir el panel | http://localhost:8501 |
| Ver los veredictos crudos | `docker compose logs -f nids` |
| Ver solo normales en el log | `docker compose logs nids \| Select-String 'NORMAL'` |
| Ver solo ataques en el log | `docker compose logs nids \| Select-String 'ATAQUE'` |
| Ver el umbral efectivo | `Get-Content .\output\nids_runtime.json` |
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

En el menú:

- `1` → solo tráfico normal (filas 🟢 NORMAL, umbral 0.30).
- `2`, `3`, `4` → ataques individuales (umbral 0.05).
- `5` → los tres ataques.
- `6` → un ataque + tráfico normal en paralelo (pregunta cuál).
- `7` → salir.

Después abrí **http://localhost:8501**. Al terminar, respondé `n` a
`¿Volver al menú? (s/n)` y `s` a `¿Apagar la demo? (s/n)`.

Eso es todo.
