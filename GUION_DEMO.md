# Cómo demostrarlo — paso a paso

Esta es la guía práctica. Al final vas a tener **4 cosas en pantalla** mostrando
el ataque y la detección en vivo.

---

## Qué vas a mostrar (el montaje)

```
┌─────────────────────┬─────────────────────┐
│ TERMINAL A          │  NAVEGADOR          │
│ NIDS capturando     │  Dashboard          │
│ ALERTA score=0.797  │  (se actualiza solo │
│ ALERTA score=0.797  │   cada 2 segundos)  │
│ ALERTA score=0.801  │                     │
├─────────────────────┼─────────────────────┤
│ TERMINAL B          │  TERMINAL C         │
│ Atacante            │  (opcional)         │
│ >>> [1/3] SYN flood │  docker compose ps  │
│    Ataques listos   │                     │
└─────────────────────┴─────────────────────┘
```

**El truco**: no levantas todo de golpe. Primero el NIDS, después el atacante.
Así el jurado VE la pantalla vacía y luego las alertas apareciendo.

---

## Preparación (la víspera, no el día)

```powershell
# 1. Verifica que el proyecto responde
uv run pytest
uv run python scripts/demo.py

# 2. Verifica que Docker está listo
docker compose config

# 3. Primer build (tarda unos minutos, hazlo HOY no mañana)
docker compose build
```

Deja todo bajado y construido. **El día de la presentación no quieres estar
esperando un `pip install` de 5 minutos delante del jurado.**

---

## El guion (con lo que dices y lo que ves)

### PASO 0 — Abre el dashboard (10 s)

Abre el navegador en `http://localhost:8501` cuando lo levantes en el paso 2.
De momento no hace falta.

### PASO 1 — Arranca el NIDS y la víctima (30 s)

**Terminal A:**
```powershell
docker compose up nids victim
```

**Lo que vas a ver:**
```
nids-detector  | NIDS-ML en vivo - iface=eth0
nids-detector  | modelo: random_forest   umbral: 0.05
nids-detector  | Capturando en eth0... Ctrl-C para terminar.
```

**Lo que dices:**
> "El NIDS arrancó y está capturando tráfico en la interfaz. Ahora mismo no hay
> alertas porque no hay tráfico anómalo — solo vemos el latido de la red."

Deja esta terminal visible. **Aquí van a aparecer las alertas.**

### PASO 2 — Abre el dashboard (20 s)

**Terminal B (nueva):**
```powershell
docker compose up dashboard
```

Se abre el navegador solo. Si no, andá a `http://localhost:8501`.

**Lo que vas a ver:** la banda superior en `EN VIVO`, la tira de indicadores en
cero, el feed vacío con *"Sin eventos todavía"*, y el **panel de control con un
botón por cada ataque**: SYN flood, Escaneo de puertos, Inundación HTTP, Todos,
Tráfico normal.

**Lo que dices:**
> "Esta es la visualización. Está en cero porque todavía no hay ataques. Y desde
> acá mismo los puedo lanzar: no necesito tocar la terminal."

### PASO 3 — Lanza el ataque (2 min) ← **EL MOMENTO**

Tenés dos formas. **La recomendada para impresionar:**

**Desde el navegador:** hacé clic en **Todos** en el panel de control.

**O desde la Terminal C (nueva):**
```powershell
docker compose up attacker
```

**Lo que vas a ver en Terminal C:**
```
nids-attacker  | >>> [1/3] SYN flood (perfil neptune)
nids-attacker  |     SYN flood terminado (400 paquetes)
nids-attacker  | >>> [2/3] Escaneo de puertos (perfil nmap)
nids-attacker  |     Escaneo terminado (300 puertos)
nids-attacker  | >>> [3/3] Inundacion HTTP (perfil satan)
nids-attacker  |     Flood HTTP terminado (60 peticiones)
```

**Y SIMULTÁNEAMENTE, en Terminal A, van apareciendo:**
```
nids-detector  | ALERTA score=0.797 tcp/http flag=S0 src_bytes=0 serror=1.00
nids-detector  | ALERTA score=0.797 tcp/http flag=S0 src_bytes=0 serror=1.00
nids-detector  | ALERTA score=0.797 tcp/http flag=S0 src_bytes=0 serror=1.00
nids-detector  | ALERTA score=0.801 tcp/http  flag=S1 src_bytes=1184 serror=0.00
```

**Y en el navegador**, el dashboard se actualiza solo:
| hora | veredicto | score | proto | servicio | flag | paquetes |
|---|---|---|---|---|---|---|
| 14:32:07 | ATAQUE | 0.797 | tcp | http | S0 | 1 |
| 14:32:07 | ATAQUE | 0.797 | tcp | http | S0 | 1 |
| 14:32:11 | ATAQUE | 0.801 | tcp | http | S1 | 16 |

**Lo que dices** (señalando la Terminal A):
> "Acá está. El atacante lanzó un SYN flood y las alertas están apareciendo en
> vivo. Miren la línea: `flag=S0` significa SYN sin respuesta —nadie contesta— y
> `serror_rate=1.00` dice que el 100% de los intentos falló. El modelo no
> adivina: lee la señal del flujo."

**Y señalando el navegador:**
> "Y la visualización se actualiza sola, sin recargar. Cada fila es un flujo
> clasificado como malicioso."

### PASO 4 — El resumen (30 s)

Cuando el atacante termina, **Terminal A** imprime:

```
Resumen en vivo (90s)
  paquetes capturados   1 112
  flujos analizados     400
  alertas emitidas      400
  tasa de alerta        100.00%
```

**Lo que dices:**
> "En 90 segundos capturó 1 112 paquetes, armó 400 flujos y detectó los tres
> ataques. Con 0.34 milisegundos de latencia por flujo: eso es tiempo real."

### PASO 5 — Cierre con las métricas (30 s)

**Terminal B** (Ctrl-C para parar Streamlit) y luego:

```powershell
uv run python scripts/demo.py
```

**Lo que vas a ver:**
```
KDDTest+.txt real: 22544 flujos, umbral 0.05
| accuracy        | 0.9310  |
| precision       | 0.9254  |
| recall          | 0.9559  |
| f1              | 0.9404  |
F1=0.9404 recall=0.9559 -> CUMPLE
```

**Lo que dices:**
> "Y sobre 22 544 flujos reales que el modelo nunca vio: F1 0.94, recall 0.956.
> El cross-validation daba 0.998 y el test 0.94 — esa diferencia es el novelty
> effect de NSL-KDD: el test tiene ataques que no están en el train. Por eso un
> 99% en benchmark no significa nada en producción."

---

## Atajos para no escribir todo

Si algo falla al tipear, estos comandos te salvan:

```powershell
docker compose up nids victim    # solo el NIDS
docker compose up attacker       # solo el ataque
docker compose down              # limpiar todo
docker compose ps                # ver qué está corriendo
docker compose logs -f nids      # ver solo los logs del NIDS
```

---

## Ensayo SIN Docker (hazlo hoy mismo)

No necesitas Docker para practicar la narración. En **dos terminales**:

**Terminal 1 — el dashboard:**
```powershell
uv run streamlit run dashboard.py
```

**Terminal 2 — el "NIDS" (replay con ritmo):**
```powershell
uv run python -m src.replay --pcap output/syn_flood.pcap --pace 1.5
```

`--pace 1.5` hace una pausa entre ventanas, así las alertas salen **espaciadas
como en una captura real** en vez de todas de golpe. Es el mismo código de
producción; solo cambia el ritmo de la salida.

**Lo que verás:** las alertas apareciendo cada 1.5 s en la Terminal 2, y el
dashboard actualizándose solo en el navegador. Es exactamente la misma
experiencia que con Docker, pero sin contenedores.

> **Ojo con el orden**: `scripts/demo.py` limpia las alertas al terminar. Si
> quieres que el dashboard tenga datos, corre el **replay al final**:
>
> ```powershell
> uv run python scripts/demo.py                                # 1. evaluación
> uv run python -m src.replay --pcap output/syn_flood.pcap --pace 1.5  # 2. alertas
> # 3. abre el dashboard → ahora sí tiene qué mostrar
> ```

### Repetir cada ataque por separado

```powershell
uv run python -m src.replay --pcap output/syn_flood.pcap  --pace 1.5
uv run python -m src.replay --pcap output/port_scan.pcap  --pace 1.5
uv run python -m src.replay --pcap output/volumetric.pcap --pace 1.5
```

Cada uno corresponde a un perfil de ataque distinto. Puedes narrarlos de a uno.

---

## Si algo falla (escalera de respaldo)

En este orden. **Uno va a funcionar.**

| # | Qué hacer | Cuándo |
|---|---|---|
| 1 | Reintentar `docker compose up attacker` | Docker está lento |
| 2 | `uv run python -m src.replay --pcap output/syn_flood.pcap` | Docker no responde |
| 3 | `uv run python scripts/demo.py` | Todo lo demás falla |
| 4 | Mostrar la salida de `demo.py` guardada en .txt | Modo pánico |

**Antes de presentar**, guarda la salida de `demo.py` en un archivo:

```powershell
uv run python scripts/demo.py > DEMO_RESPALDO.txt 2>&1
```

Si todo se cae, abres ese archivo y sigues explicando. Nadie nota la diferencia.

---

## Ensayo en seco (hazlo 2 veces)

1. `docker compose down` — limpia todo
2. Sigue los pasos 1 → 5 en orden
3. Cronometra: debe darte **menos de 6 minutos**

Si el paso 3 no muestra alertas, revisa:
- ¿Terminal A dice "Capturando en eth0"? Si no, el NIDS no arrancó
- ¿El atacante usa el mismo netns? Verifica `network_mode: service:nids` en el compose
- ¿Pasaron los 12 segundos de `NIDS_WARMUP`? El ataque espera a que el NIDS esté listo

---

## Preguntas que te van a hacer

**"¿Cómo sé que no está haciendo trampa?"**
El replay y la captura en vivo usan el **mismo** `src/features.py` y el mismo
artefacto. `tests/test_live.py` verifica que el camino en vivo y el de replay
producen el **mismo resultado con los mismos paquetes**.

**"¿Por qué el atacante comparte la red con el NIDS?"**
Porque un bridge de Docker es un switch, no un hub: solo reenvía al puerto
destino. Si fueran contenedores hermanos, el NIDS no vería el tráfico. Detalle
en `docker/README.md`.

**"¿Por qué el umbral es 0.05 y no 0.5?"**
El 0.5 es el default de scikit-learn, que maximiza accuracy —no detectar—. Con
0.5 el recall caía a 0.64: se perdía un tercio de los ataques.

**"¿Es adaptativo?"**
No. Es clasificación supervisada batch: estático hasta reentrenar. Decir
"adaptativo" sería incorrecto.

**"¿Funciona con tráfico real de internet?"**
No lo garantizo. Los benchmarks no predicen tráfico real, y ese salto es
justamente lo que mediría un lab con VMs.

---

## Lo que NO cubre todavía (dilo antes de que lo pregunten)

El alcance de la propuesta incluye **evaluación comparativa de modelos ML**
(Random Forest, XGBoost, etc.). El sistema corre con **Random Forest** y está
operativo; la comparación contra XGBoost y LightGBM queda como trabajo
siguiente. Las dependencias ya están instaladas, solo falta el módulo de
comparación.

**Mejor decirlo vos** que esperar a que te lo señalen.
