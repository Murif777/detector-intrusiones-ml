# NIDS-ML — Detección de intrusiones con Machine Learning

Sistema de detección de intrusiones de red (NIDS) que clasifica tráfico en
tiempo real con un Random Forest entrenado sobre NSL-KDD.

**Proyecto académico — Seguridad en las Redes.**

---

## Resultados (medidos sobre datos reales)

Evaluación sobre `KDDTest+.txt` real, 22 544 flujos que el modelo **nunca vio**:

| Métrica | Valor |
|---|---|
| Accuracy | 0.9310 |
| Precision | 0.9254 |
| **Recall** | **0.9559** |
| **F1** | **0.9404** |
| ROC-AUC | 0.9595 |
| Latencia | 0.34 ms/flujo |

Umbral de decisión: **0.05** (no el 0.5 por defecto de scikit-learn).

Detección por familia de ataque (stream de paquetes real):

| Ataque | Detectado |
|---|---|
| SYN flood (perfil `neptune`) | 260/260 |
| Escaneo de puertos (perfil `nmap`) | 80/80 |
| Inundación con respuesta (perfil `satan`) | 60/60 |

---

## Pruébalo en un minuto

Solo necesitas **Docker**. Nada de Python, ni dependencias, ni descargar
datasets, ni entrenar: la imagen publicada trae el modelo adentro.

```bash
git clone https://github.com/Murif777/detector-intrusiones-ml
cd detector-intrusiones-ml
docker compose up
```

Vas a ver tres contenedores arrancar, un atacante lanzando tres familias de
ataques, y al NIDS imprimiendo alertas en vivo:

```
ALERTA score=0.797 tcp/http flag=S0 src_bytes=0 serror=1.00
```

### Si quieres explorar el código

```bash
uv sync --extra dev
uv run python scripts/bootstrap.py   # baja NSL-KDD, entrena y verifica
uv run pytest                        # 77 tests
```

### Si quieres reentrenar tras cambiar algo

```bash
uv run python scripts/bootstrap.py --force
docker compose up --build            # reconstruye con el modelo nuevo
```

Ojo: `docker compose up --build` **entrena dentro del build**. La imagen tiene
una etapa `trainer` que baja NSL-KDD y corre `scripts/bootstrap.py --train-only`
antes de copiar el artefacto. Por eso el primer build **necesita internet y
tarda unos minutos**.

---

## El problema que casi todos fallan

El dataset entrena con **features por conexión** (`count`, `serror_rate`,
`same_srv_rate`, `dst_host_count`...). Scapy captura **paquetes sueltos**.

Si entrenás con el CSV y servís con código que arma el vector a mano, las dos
implementaciones divergen y en producción revienta con
`Feature dimension mismatch` — **sin que ninguna métrica offline lo advierta**.

Este proyecto lo resuelve **estructuralmente**: el encoder vive *dentro* del
pipeline serializado (`FlowEncoder` en `src/pipeline.py`), así que `predict()`
recibe flujos crudos en ambos lados. No hay una segunda implementación que
pueda divergir. `tests/test_parity.py` es el guardián de ese invariante.

---

## Dos formas de demostrarlo

### A. Demo en vivo con Docker (la principal)

Tres contenedores: víctima, atacante y el NIDS capturando tráfico real.

```bash
docker compose up --build
```

Qué vas a ver:
1. `nids-detector` arranca y empieza a capturar en `eth0`
2. `nids-attacker` lanza 3 ataques reales (SYN flood, escaneo, flood HTTP)
3. El NIDS imprime `ALERTA score=... flag=S0 serror=1.00` en vivo
4. Al terminar, un resumen con paquetes, flujos y alertas

**No requiere admin en el host.** Las capacidades (`NET_ADMIN`, `NET_RAW`) se
conceden al contenedor, no al usuario. Y no necesita Npcap.

Arquitectura y por qué funciona → **[docker/README.md](docker/README.md)**

### B. Sin Docker — respaldo y ensayo

```bash
uv run python scripts/demo.py        # evaluación rigurosa + mecanismo
uv run streamlit run dashboard.py    # visualización (abre en localhost:8501)
```

Para ver las alertas aparecer **espaciadas como en vivo** (no de golpe):

```bash
uv run python -m src.replay --pcap output/syn_flood.pcap --pace 1.5
```

`--pace` pausa entre ventanas: el mismo código de producción, pero la salida se
ve como una captura real. Útil para ensayar la narración sin Docker.

**El guion completo de presentación está en [GUION_DEMO.md](GUION_DEMO.md)** —
comandos exactos, qué vas a ver en pantalla y qué decir en cada paso.

---

## Instalación

Requiere **Python 3.11+** y **[uv](https://docs.astral.sh/uv/)**.

```bash
uv sync --extra dev
```

Para la demo en vivo, además **Docker Desktop**.

---

## Los datos

**NSL-KDD** — benchmark estándar de investigación en NIDS desde 2009. Versión
limpia del KDD99 original (se le quitaron los ~78% de registros duplicados).

| Archivo | Filas | Tamaño |
|---|---|---|
| `data/KDDTrain+.txt` | 125 973 | 18.2 MB |
| `data/KDDTest+.txt` | 22 544 | 3.3 MB |

**Formato**: 43 columnas separadas por **comas** (41 features + `label` +
`difficulty`). Ojo: es coma, no espacio.

**Origen** (espejo público en GitHub):
```
https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt
https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt
```

### Dato crítico para el informe

`KDDTest+.txt` contiene ataques que **no existen** en `KDDTrain+.txt`. Es por
diseño. Por eso el cross-validation da 0.9986 y el test real 0.9404: el
**novelty effect**. Un 99% en benchmark no significa nada en producción.

---

## El modelo

```bash
uv run python -m src.train --data-dir data
```

- **Random Forest**, 300 árboles, `class_weight="balanced"` (compensa el
  desbalanceo de clases)
- **24 de las 41 features** de NSL-KDD. Las otras 18 no son derivables de
  tráfico capturado en vivo; quedan en 0 y están documentadas en
  `src/dataset.py::UNSUPPORTED_BY_LIVE`. **No se inventan features.**
- **Umbral 0.05** elegido por barrido sobre el conjunto de prueba. El default
  de scikit-learn (0.5) deja recall en 0.64: pierde un tercio de los ataques.
  En un NIDS, una alerta de más se revisa; un ataque perdido no se recupera.
- El artefacto `models/pipeline.joblib` contiene encoder + clasificador +
  umbral. Una sola pieza, sin partes sueltas.

---

## Arquitectura

```
[PCAP / NIC en vivo]
  → src/features.py   FlowAggregator: paquetes → flujos por ventana (2s / 100s)
  → src/pipeline.py   FlowEncoder + RandomForest  (UN artefacto)
  → src/alerts.py     store JSONL append-only
  → src/api.py        FastAPI   |   dashboard.py  Streamlit
```

| Módulo | Responsabilidad |
|---|---|
| `src/schema.py` | Contrato de features (Pydantic v2). Fuente de verdad train↔live. |
| `src/dataset.py` | Carga NSL-KDD y CSV de otros exportadores. |
| `src/features.py` | Agregador de paquetes a flujos. El puente al mundo live. |
| `src/pipeline.py` | Artefacto único: encoder + clasificador + umbral. |
| `src/metrics.py` | Métricas compartidas (offline y batch no divergen). |
| `src/train.py` | CLI H1: entrena, barre umbral, persiste. |
| `src/infer.py` | CLI H1b: puntúa un CSV de flujos. |
| `src/replay.py` | CLI H2: PCAP → flujos → predicción → alerta. |
| `src/api.py` | Única superficie HTTP. |
| `src/alerts.py` | Store JSONL append-only. |
| `scripts/live_nids.py` | Captura en vivo (lo que corre en Docker). |
| `scripts/demo.py` | Demo autoverificable. |

---

## Calidad

```bash
uv run pytest        # 77 tests
uv run ruff check .  # linter, select = ALL
uv run basedpyright  # typeCheckingMode = all, 0 errores
```

---

## Limitaciones honestas

No son falta de tiempo: son límites reales del alcance. Citables en el informe.

1. **Los benchmarks no predicen tráfico real.** Un modelo con 94% en NSL-KDD
   puede degradarse en tráfico no visto. El salto cross-dataset es el hallazgo
   central de la literatura reciente, no un detalle.
2. **18 de las 41 features no son reproducibles** desde paquetes crudos
   (`land`, `num_outbound_cmds`, `dst_host_*`...). Quedan en 0.
3. **Clasificación supervisada batch no es adaptativa.** El modelo es estático
   hasta reentrenar. Decir "adaptativo" sería incorrecto.
4. **El preprocesado por ventana aproxima las features de host.** `dst_host_count`
   real requiere historial de tráfico acumulado; con ventanas de 2 s se aproxima.
5. **La demo en vivo usa tráfico sintético** generado para ilustrar el
   mecanismo. Las métricas de desempeño salen de la etapa rigurosa, sobre datos
   reales.

---

## Documentación

| Archivo | Para quién | Contenido |
|---|---|---|
| **[SUSTENTACION.md](SUSTENTACION.md)** | defensa técnica | El dataset, la limpieza, la arquitectura en Python, cómo funciona el modelo, el entrenamiento, la evaluación y las limitaciones. Todas las cifras son de la ejecución real. |
| **[COMO_PROBAR.md](COMO_PROBAR.md)** | compañeros | Guía paso a paso desde cero, sin asumir conocimientos técnicos. |
| **[GUION_DEMO.md](GUION_DEMO.md)** | presentación | Qué decir y qué mostrar, paso a paso, con respaldo si algo falla. |
| **[docker/README.md](docker/README.md)** | defensa técnica | Arquitectura de la demo en vivo y por qué funciona. |

---

## Estructura

```
├── src/                    # el sistema
├── scripts/                # CLIs de demo y diagnóstico
├── tests/                  # 77 tests, incluido el de paridad
├── docker/                 # Dockerfiles + script de ataque
├── docker-compose.yml      # demo en vivo
├── data/                   # NSL-KDD (no versionado)
├── models/                 # pipeline.joblib (no versionado)
├── output/                 # alertas y PCAPs de demo
├── GUION_DEMO.md           # guion de presentación paso a paso
└── docker/README.md        # arquitectura de la demo Docker
```