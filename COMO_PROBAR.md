# Cómo probar el NIDS en tu PC — paso a paso

Guía para correr el proyecto en tu computador sin saber nada de programación.

**Tiempo total: 20 minutos** (la mayoría es esperar una descarga).

No necesitas instalar Python, ni saber programar, ni descargar datos. Solo dos
programas y tres comandos.

---

## Antes de empezar: ¿qué vamos a hacer?

El proyecto detecta ataques informáticos en una red. Cuando lo corras vas a ver:

1. Se levantan **tres programas** en tu PC (una víctima, un atacante y el detector)
2. El atacante lanza **3 ataques reales**
3. El detector **los detecta y avisa** en la pantalla

Todo pasa dentro de tu computador. **No vas a atacar nada real.**

---

## PARTE 1 — Instalar los dos programas que hacen falta

### 1.1 Instalar Docker Desktop

Docker es el programa que corre el proyecto sin que tengas que instalar nada más.

1. Entrá a: **https://www.docker.com/products/docker-desktop/**
2. Hacé clic en **Download for Windows**
3. Abrí el archivo que se descargó (`Docker Desktop Installer.exe`)
4. Dale **Next** a todo. Dejá las opciones como vienen.
5. **Cuando termine, REINICIÁ TU COMPUTADOR.** Esto es obligatorio.

> Si no te deja instalar, necesitás permisos de administrador. Pedíselos a quien
> administra tu PC, o usá tu computador personal.

### 1.2 Verificar que Docker quedó bien

Después del reinicio:

1. Abrí **Docker Desktop** desde el menú Inicio
2. Esperá a que aparezca un **ícono de ballena** en la esquina inferior derecha
3. **La ballena tiene que estar quieta y de color normal**, no girando ni en rojo

> ⚠️ **Docker Desktop tiene que estar ABIERTO todo el tiempo.** Si lo cerrás,
> el proyecto deja de funcionar. Si no lo ves, abrilo desde el menú Inicio.

**✅ Si ves la ballena abajo a la derecha, seguí a la PARTE 2.**

---

## PARTE 2 — Descargar el proyecto

### Opción fácil (sin instalar nada)

1. Entrá a: **https://github.com/Murif777/detector-intrusiones-ml**
2. Hacé clic en el botón verde **`< > Code`**
3. Hacé clic en **Download ZIP**
4. Buscá el archivo en tu carpeta de **Descargas**
5. Clic derecho → **Extraer todo...** → elegí una carpeta fácil de encontrar,
   por ejemplo `C:\nids`
6. Anotá esa ruta, la vas a necesitar

### Opción si ya tenés Git instalado

Abrí PowerShell y escribí esto:

```powershell
git clone https://github.com/Murif777/detector-intrusiones-ml.git
```

Se va a crear una carpeta llamada `detector-intrusiones-ml` en tu carpeta de
usuario.

**✅ Si tenés la carpeta con `docker-compose.yml` adentro, seguí a la PARTE 3.**

---

## PARTE 3 — Abrir la terminal en la carpeta correcta

Esto es lo que más confunde, así que va despacio.

1. Abrí la carpeta del proyecto en el **Explorador de archivos**
   (por ejemplo `C:\nids\detector-intrusiones-ml`)
2. Verificá que **adentro** de esa carpeta se vea un archivo llamado
   `docker-compose.yml`
3. En la **barra de direcciones** del Explorador (arriba), borrá lo que hay y
   escribí la palabra: `powershell`
4. Presioná **Enter**

> **Truco:** también podés hacer clic derecho en un espacio vacío de la carpeta
> → **"Abrir en Terminal"** (Windows 11) o **"Abrir ventana de PowerShell aquí"**
> (Windows 10).

Se abre una ventana azul o negra. Ahí vas a escribir los comandos.

**✅ Verificación:** escribí este comando y presioná Enter:

```powershell
dir
```

Tenés que ver en la lista el archivo `docker-compose.yml`.

- **Lo ves** → seguí a la PARTE 4
- **No lo ves** → estás en la carpeta equivocada. Volvé al inicio de esta parte.

---

## PARTE 4 — Arrancar el proyecto

Escribí esto en la terminal y presioná Enter:

```powershell
docker compose up
```

Y esperá. **La primera vez tarda entre 5 y 15 minutos** porque descarga los
programas (unos 500 MB). Vas a ver un montón de texto pasando. **Es normal.**

### Qué vas a ver cuando arranque

Primero algo así:

```
nids-detector  | modelo: random_forest   umbral: 0.05
nids-detector  | Capturando en eth0... Ctrl-C para terminar.
```

Después de ~12 segundos empieza el ataque:

```
nids-attacker  | >>> [1/3] SYN flood (perfil neptune)
nids-detector  | ALERTA score=0.797 tcp/http flag=S0 src_bytes=0 serror=1.00
nids-detector  | ALERTA score=0.797 tcp/http flag=S0 src_bytes=0 serror=1.00
nids-detector  | ALERTA score=0.797 tcp/http flag=S0 src_bytes=0 serror=1.00
```

### 🎯 Lo importante: esas líneas `ALERTA`

**Eso significa que el sistema está funcionando.** Está viendo el ataque y
avisando en el momento.

Vas a ver tres ataques en total:

| # | Ataque | Qué verás |
|---|---|---|
| 1 | SYN flood | Muchas `ALERTA ... flag=S0 serror=1.00` |
| 2 | Escaneo de puertos | Más `ALERTA ... flag=S0` |
| 3 | Inundación HTTP | `ALERTA ... flag=S1 src_bytes=1184` |

Al final:

```
nids-attacker  | Ataques completados. Revisa la salida del NIDS.
```

**Dejá la ventana abierta y andá a la PARTE 5.**

---

## PARTE 5 — Ver el panel de alertas en el navegador

Además de las líneas de texto, hay una **página web** que muestra las alertas
en una tabla.

**No necesitás instalar nada.** Ya viene incluida.

### Cómo verla

1. **Dejá la terminal de la PARTE 4 corriendo** (no la cierres). El NIDS tiene
   que seguir capturando.

2. Abrí **otra** terminal en la misma carpeta (repetí la PARTE 3)

3. Escribí esto y presioná Enter:

```powershell
docker compose up dashboard
```

4. Esperá ~30 segundos a que diga algo como `You can now view your Streamlit app`

5. Abrí tu navegador (Chrome, Edge, el que uses) y entrá a:

   **http://localhost:8501**

### Qué vas a ver

- Arriba: **Modelo entrenado: si**, y tres números (Eventos, Ataques, Normales)
- Abajo: **la tabla de alertas**, cada fila es un flujo que el sistema detectó

> 💡 **La tabla se actualiza sola cada 2 segundos.** Si lanzás un ataque con la
> ventana abierta, vas a ver las filas aparecer en vivo, sin recargar.

Si ves "Sin alertas todavía", esperá a que el atacante lance el primer ataque.

### Para cerrarlo

En la terminal del dashboard: **`Ctrl` + `C`**

---

## PARTE 6 — Apagar todo

Cuando termines, **en cada terminal abierta**:

1. Apretá **`Ctrl` + `C`** (las dos teclas juntas)
2. Esperá unos segundos
3. Después escribí una vez, en cualquiera de ellas:

```powershell
docker compose down
```

Eso apaga y limpia todo. **Hacelo siempre que termines.**

### Para volver a arrancarlo

```powershell
docker compose up
```

Ya es instantáneo, todo está descargado.

Si además querés el panel:

```powershell
docker compose up dashboard
```

en otra terminal, y abrís http://localhost:8501

---

## Si algo sale mal

| Lo que ves | Qué significa | Qué hacer |
|---|---|---|
| `docker: command not found` | Docker no está instalado | Volvé a la PARTE 1.1 |
| `Cannot connect to the Docker daemon` | Docker Desktop está cerrado | Abrí Docker Desktop y esperá la ballena |
| Se queda pegado en `Pulling` | Está descargando (500 MB) | Esperá. Puede tardar 15 min |
| `port is already allocated` | Otro programa usa el puerto | `docker compose down` y reintentá |
| No aparece ninguna `ALERTA` | El ataque no llegó al detector | Esperá los 12 s de calentamiento. Si sigue, `docker compose down` y de nuevo |
| Todo rojo y no entiendo nada | Algo se rompió | `docker compose down`, esperá 10 s, `docker compose up` |
| `Access is denied` | Falta permiso de administrador | Clic derecho en la terminal → **Ejecutar como administrador** |

### La solución universal

Si nada funciona, esto resuelve el 90% de los casos:

```powershell
docker compose down
```

Esperá 10 segundos, cerrá Docker Desktop, volvé a abrirlo, esperá la ballena, y:

```powershell
docker compose up
```

---

## Preguntas que te van a surgir

**¿Esto ataca algo de verdad?**
No. Los tres programas corren **dentro de tu computador**, en una red interna
aislada que no toca internet ni tu red real. La víctima es un programa, no una
máquina.

**¿Puedo romper algo?**
No. Todo vive dentro de Docker. Cuando hacés `docker compose down`, desaparece.

**¿Ocupa mucho espacio?**
Unos 2 GB entre Docker y las imágenes. Si necesitás liberar espacio, podés
borrar las imágenes desde Docker Desktop → Images.

**¿Necesito internet?**
Solo la primera vez, para descargar. Después funciona sin conexión.

**¿Por qué usa Kali Linux?**
Kali es la distribución que usan los profesionales de seguridad para probar
sistemas. El contenedor "atacante" la usa porque trae las herramientas de ataque.

---

## Qué está pasando por dentro (por si te preguntan)

```
Tu computador
└── Red interna de Docker (aislada, no toca internet)
    ├── victim     → un servidor web de prueba
    ├── nids       → el detector: lee el tráfico y lo clasifica
    ├── attacker   → lanza los 3 ataques
    └── dashboard  → la página web de alertas
```

El detector **no adivina**: cada flujo de tráfico se convierte en 24 números
(duración, bytes, cantidad de paquetes, tasa de error...) y un modelo de
Machine Learning entrenado con 125 973 ejemplos decide si es normal o ataque.

**Resultado del modelo:** detecta el 95.6% de los ataques, con 92.5% de acierto
en sus alertas, y tarda 0.34 milisegundos por flujo.

---

## Chuleta para tener a mano

| Quiero... | Comando |
|---|---|
| Arrancar el NIDS y el ataque | `docker compose up` |
| Arrancar el panel web | `docker compose up dashboard` (otra terminal) |
| Ver el panel | abrir http://localhost:8501 |
| Apagar todo | `Ctrl` + `C` y después `docker compose down` |
| Ver qué está corriendo | `docker compose ps` |
| Ver solo los logs del NIDS | `docker compose logs -f nids` |

### Resumen ultra corto

```powershell
docker compose up              # arranca y muestra las alertas en texto
docker compose up dashboard    # (otra terminal) panel web en localhost:8501
docker compose down            # apaga todo
```

Eso es todo.
