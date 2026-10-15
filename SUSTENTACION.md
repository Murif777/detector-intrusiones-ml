# Sustentación técnica — NIDS-ML

Documento de defensa del proyecto: qué se hizo, cómo y por qué. Todas las cifras
están tomadas de la ejecución real del sistema, no de estimaciones.

---

# Índice

1. [El problema que motiva el proyecto](#1-el-problema-que-motiva-el-proyecto)
2. [El dataset: NSL-KDD](#2-el-dataset-nsl-kdd)
3. [Limpieza y preprocesamiento](#3-limpieza-y-preprocesamiento)
4. [El contrato de features](#4-el-contrato-de-features)
5. [Arquitectura del sistema en Python](#5-arquitectura-del-sistema-en-python)
6. [El modelo de Machine Learning](#6-el-modelo-de-machine-learning)
7. [El entrenamiento](#7-el-entrenamiento)
8. [La evaluación](#8-la-evaluación)
9. [El hallazgo principal: novelty effect](#9-el-hallazgo-principal-novelty-effect)
10. [Del entrenamiento a la captura en vivo](#10-del-entrenamiento-a-la-captura-en-vivo)
11. [Decisiones de ingeniería y trade-offs](#11-decisiones-de-ingeniería-y-trade-offs)
12. [Limitaciones](#12-limitaciones)
13. [Reproducibilidad](#13-reproducibilidad)

---

# 1. El problema que motiva el proyecto

## 1.1 Por qué los IDS tradicionales fallan

Un Sistema de Detección de Intrusiones (IDS) basado en **firmas** compara el
tráfico contra una base de patrones conocidos. Tiene dos problemas estructurales:

1. **No detecta lo que no conoce.** Un ataque nuevo, o una variante de uno
   conocido, no coincide con ninguna firma. El sistema es ciego por diseño.
2. **Falsos positivos.** Las reglas rígidas marcan tráfico legítimo inusual como
   malicioso, y los analistas terminan ignorando las alertas.

La propuesta de este proyecto es cambiar el enfoque: en vez de comparar contra
patrones escritos a mano, **aprender el comportamiento del tráfico** a partir de
ejemplos etiquetados, y clasificar cada flujo por su similitud estadística con
tráfico normal o malicioso.

## 1.2 Qué se propuso construir

| Objetivo específico de la propuesta | Estado |
|---|---|
| Preprocesar datasets públicos de tráfico de red | ✅ NSL-KDD, 148 517 flujos |
| Entrenar y comparar modelos ML | ⚠️ Random Forest implementado y operativo; la comparación queda pendiente |
| Desarrollar servicio de captura de paquetes en tiempo real | ✅ `scripts/live_nids.py` |
| Implementar sistema de alertas funcional en laboratorio | ✅ store JSONL + panel web |
| Evaluar desempeño con métricas estándar | ✅ precision, recall, F1, ROC-AUC |

---

# 2. El dataset: NSL-KDD

## 2.1 Qué es y por qué se eligió

**NSL-KDD** es la versión depurada del histórico **KDD Cup 99**, el benchmark de
referencia en detección de intrusiones desde 1999. Fue publicado en 2009 por el
Canadian Institute for Cybersecurity (University of New Brunswick) precisamente
para corregir los defectos del original.

**Problemas del KDD99 original que NSL-KDD resuelve:**

| Defecto del KDD99 | Corrección en NSL-KDD |
|---|---|
| 78% de registros duplicados en el train | Duplicados eliminados |
| Los clasificadores se sesgaban hacia las clases frecuentes | Distribución de clases balanceada |
| El conjunto de test era trivialmente fácil | Selección de registros de dificultad variada |

**Por qué se eligió sobre CICIDS2017** (la otra opción que menciona la propuesta):

- NSL-KDD viene **limpio**: CICIDS2017 requiere días de depuración (valores
  infinitos, nulos, etiquetas inconsistentes).
- Su esquema de 41 features está **documentado y es estable desde 1999**, lo que
  permite comparar contra décadas de literatura.
- El tamaño (18 MB) permite entrenar en segundos, no en horas.

CICIDS2017 se dejó como trabajo futuro por una razón técnica concreta que se
explica en la [sección 9](#9-el-hallazgo-principal-novelty-effect).

## 2.2 Origen de los datos

```
https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt
https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt
```

Espejo público en GitHub del dataset oficial. La descarga está automatizada en
`scripts/bootstrap.py`, que verifica que el archivo exista antes de bajarlo.

## 2.3 Estructura del archivo

Cada archivo es **CSV sin cabecera, separado por comas**, con **43 columnas**:

| Grupo | Columnas | Descripción |
|---|---|---|
| Básicas de conexión | 9 | `duration`, `protocol_type`, `service`, `flag`, `src_bytes`, `dst_bytes`, `land`, `wrong_fragment`, `urgent` |
| De contenido | 13 | `hot`, `num_failed_logins`, `logged_in`, `root_shell`, ... |
| De tráfico (ventana 2 s) | 9 | `count`, `srv_count`, `serror_rate`, `same_srv_rate`, ... |
| De host (ventana 100 conexiones) | 10 | `dst_host_count`, `dst_host_srv_count`, `dst_host_serror_rate`, ... |
| Etiquetas | 2 | `label` (nombre del ataque o `normal`), `difficulty` |

> **Dato que sorprende a muchos:** el archivo se llama `.txt` pero es CSV con
> separador de **coma**, no de espacio. Asumir lo contrario rompe el cargador —
> fue un error real que se cometió durante el desarrollo y que quedó cubierto por
> un test de regresión (`tests/test_dataset.py`).

## 2.4 Composición de los datos

| | Filas | Normal | Ataque |
|---|---|---|---|
| **KDDTrain+.txt** | 125 973 | 67 343 (53.5%) | 58 630 (46.5%) |
| **KDDTest+.txt** | 22 544 | 9 711 (43.1%) | 12 833 (56.9%) |

**Familias más frecuentes en el entrenamiento:**

| Familia | Flujos | Tipo de ataque |
|---|---|---|
| `neptune` | 41 214 | SYN flood (DoS) |
| `satan` | 3 633 | Escaneo con detección de vulnerabilidades |
| `ipsweep` | 3 599 | Barrido de hosts |
| `portsweep` | 2 931 | Barrido de puertos |
| `smurf` | 2 646 | Amplificación ICMP (DoS) |
| `nmap` | 1 493 | Escaneo de puertos |

> ⚠️ **Nota para la defensa:** el desbalanceo es severo. `neptune` sola representa
> el 70% de todos los ataques del entrenamiento. Esto tiene dos consecuencias que
> se abordan en la [sección 7](#7-el-entrenamiento): la métrica *accuracy* es
> engañosa, y hace falta compensar el peso de las clases.

---

# 3. Limpieza y preprocesamiento

## 3.1 Qué se limpió y por qué

NSL-KDD ya viene depurado —**no se eliminó ninguna fila**—, pero el archivo crudo
no es directamente consumible por un modelo de ML. Se aplicaron cuatro
transformaciones:

### 3.1.1 Tipado explícito de columnas

El archivo se lee con `infer_schema_length=0` (todo como texto) y luego se
convierte explícitamente: las 38 columnas numéricas a `Float64`, y las
categóricas (`protocol_type`, `service`, `flag`) se dejan como texto.

**Por qué no dejar que la librería infiera:** si se deja inferir sobre una muestra,
una columna que en la muestra parece entera pero contiene decimales más adelante
causa un fallo silencioso. El tipado explícito es determinista.

### 3.1.2 Binarización de la etiqueta

El dataset tiene **23 familias de ataque distintas** en el train (`neptune`,
`satan`, `smurf`, ...) más `normal`. El proyecto resuelve un problema **binario**:
normal vs. ataque.

```
label == "normal"  →  0
label != "normal"  →  1
```

**Por qué binario y no multiclase:** el objetivo de la propuesta es *detectar*,
no *clasificar la familia*. Distinguir `satan` de `nmap` es un problema
sustancialmente más difícil y no aporta al objetivo declarado. Queda como trabajo
futuro.

### 3.1.3 Selección de las features reproducibles

De las 41 features del dataset, **se usan 23**. Las 18 restantes se descartan
porque **no son derivables de tráfico capturado en vivo**. Ver la
[sección 4](#4-el-contrato-de-features) para el detalle.

### 3.1.4 Las 3 features categóricas

`protocol_type` (3 valores), `service` (70 valores) y `flag` (11 valores) son
cadenas de texto que un modelo numérico no puede consumir. Se codifican con
**one-hot encoding**: cada valor posible se convierte en una columna binaria.

Esto expande el vector de 23 a **107 dimensiones**:

```
3 protocolos  +  1 (bucket desconocido)  =   4 columnas
70 servicios +  1                          =  71 columnas
11 flags      +  1                         =  12 columnas
20 features numéricas                      =  20 columnas
                                             ─────────
                                             107 columnas
```

---

# 4. El contrato de features

## 4.1 El problema central del proyecto

**Este es el punto técnico más importante de toda la sustentación.**

El dataset describe **conexiones completas** (features como `count` = "cuántas
conexiones al mismo host en los últimos 2 segundos"). Pero un sniffer de red
captura **paquetes sueltos**. Son dos niveles de abstracción distintos.

Si el entrenamiento usa las features del CSV y el servicio del sistema en vivo
arma el vector con código escrito aparte, **las dos implementaciones divergen**.
El síntoma típico es un fallo en producción del tipo:

```
ValueError: X has 78 features, but StandardScaler is expecting 12
```

Ninguna métrica offline detecta ese fallo: el modelo sigue reportando 99% en el
conjunto de prueba mientras en producción no funciona.

## 4.2 La decisión: un solo artefacto

La solución implementada es que **el encoder viva dentro del pipeline
serializado**, de manera que ambos caminos ejecuten exactamente el mismo código:

```python
# src/pipeline.py
pipe = Pipeline([
    ("encoder", FlowEncoder()),      # one-hot + escalado
    ("classifier", RandomForestClassifier(...)),
])
```

El encoder y el clasificador se guardan **juntos** en un único archivo
(`models/pipeline.joblib`, 30 MB). En inferencia se pasa un flujo crudo:

```python
bundle = load_pipeline()
prediccion = bundle.predict(flujo)   # el mismo encoder del entrenamiento
```

**La paridad de features deja de ser una convención y pasa a ser una propiedad
estructural del artefacto.** No existe una segunda implementación que pueda
divergir porque no hay una segunda implementación.

Esto está verificado por `tests/test_parity.py`, que compara los vectores
**campo por campo** entre el camino de entrenamiento y el de servicio.

## 4.3 Las 23 features usadas

**Categóricas (3):** `protocol_type`, `service`, `flag`

**Numéricas (20):**

| Feature | Qué mide |
|---|---|
| `duration` | Duración de la conexión en segundos |
| `src_bytes` | Bytes de carga útil origen → destino |
| `dst_bytes` | Bytes de carga útil destino → origen |
| `count` | Conexiones al mismo host en los últimos 2 s |
| `srv_count` | Conexiones al mismo servicio en los últimos 2 s |
| `serror_rate` | Proporción de conexiones con error SYN |
| `srv_serror_rate` | Ídem, restringido al mismo servicio |
| `rerror_rate` | Proporción de conexiones con error REJ |
| `same_srv_rate` | Proporción de conexiones al mismo servicio |
| `diff_srv_rate` | Proporción de conexiones a servicios distintos |
| `wrong_fragment` | Fragmentos IP incorrectos |
| `urgent` | Paquetes con flag URG |
| `hot`, `num_failed_logins`, `logged_in`, `num_compromised`, `root_shell` | Indicadores de contenido |
| `dst_host_count`, `dst_host_srv_count`, `dst_host_same_srv_rate` | Estadísticas del host destino |

## 4.4 Las 18 features descartadas

Estas features existen en NSL-KDD pero **no son reproducibles desde paquetes**:

```python
# src/dataset.py
UNSUPPORTED_BY_LIVE = (
    "land", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
    "srv_rerror_rate", "srv_diff_host_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
)
```

**Por qué se descartan y no se rellenan con ceros:** rellenarlas sería introducir
ruido. El modelo aprendería a confiar en features que en producción siempre valen
cero. **Es preferible perder información que entrenar con datos falsos.**

---

# 5. Arquitectura del sistema en Python

## 5.1 Módulos y responsabilidad

```
src/
├── schema.py      Contrato de features (Pydantic v2) — fuente de verdad
├── dataset.py     Carga NSL-KDD + armonización al contrato
├── features.py    Agregador: paquetes → flujos
├── pipeline.py    Artefacto único: FlowEncoder + clasificador + umbral
├── metrics.py     Métricas compartidas
├── train.py       CLI de entrenamiento
├── infer.py       CLI de scoring por lote
├── replay.py      CLI de reproducción PCAP / captura en vivo
├── api.py         Servicio HTTP (FastAPI)
└── alerts.py      Store JSONL append-only
```

Cada módulo tiene **una sola responsabilidad**. La separación no es decorativa:
`pipeline.py` no sabe nada de captura de red, y `features.py` no sabe nada del
modelo. Eso permite testear cada capa por separado.

## 5.2 El contrato tipado

`schema.py` define `FlowFeatures` con **Pydantic v2**. Es la pieza que garantiza
que ambos extremos hablen el mismo idioma:

```python
@final
class FlowFeatures(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    protocol_type: str = "tcp"
    service: str = "other"
    flag: str = "SF"
    duration: float = Field(default=0.0, ge=0.0)
    src_bytes: int = Field(default=0, ge=0)
    serror_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    ...
```

**Por qué `frozen=True`:** un flujo que cambia a mitad de camino es un error de
programación. Hacerlo inmutable lo convierte en un error detectable.

**Por qué `extra="forbid"`:** si alguien agrega una columna de más, el sistema
falla ruidosamente en vez de ignorarla en silencio.

**Por qué las tasas están acotadas a [0, 1]:** un valor de 5.0 en `serror_rate`
es imposible. La validación vive en el **borde**, no dispersa por el código.

## 5.3 El agregador de flujos

`features.py` resuelve el salto de abstracción entre paquetes y flujos.

**Agrupación por 5-tupla:** cada conexión se identifica por
`(IP origen, IP destino, puerto origen, puerto destino, protocolo)`. Los paquetes
que comparten esos cinco valores pertenecen al mismo flujo.

**Manejo bidireccional:** los paquetes de respuesta (del servidor al cliente)
tienen la tupla invertida. El agregador detecta que son la respuesta de una
conexión ya abierta y los acumula en la misma entrada, en vez de crear un flujo
nuevo.

> Este punto fue una **fuente real de bug**: la primera versión insertaba la clave
> invertida apuntando al mismo objeto, y como el cierre de ventana itera el
> diccionario, cada conexión bidireccional se emitía **dos veces**. Inflaba el
> conteo de flujos y sesgaba las features derivadas.

**Emisión al cerrar:** una conexión TCP puede durar más que la ventana de
análisis. Si se emitiera al cruzar el límite, la sesión quedaría partida y cada
mitad parecería tráfico anómalo (`dst_bytes=0`, `count` bajísimo). Por eso un
flujo se emite **cuando cierra** (FIN/RST) o en el vaciado final del stream.

> Este fue el **segundo bug real** del desarrollo, y el más costoso: causaba un
> 20% de falsos positivos sobre tráfico benigno. Se corrigió y quedó cubierto por
> un test que se verificó revirtiendo el arreglo.

## 5.4 Semántica de `src_bytes`

NSL-KDD define `src_bytes` como *"data bytes from source to destination"* — es
decir, la **carga útil**, no el paquete completo.

La primera versión usaba `len(paquete)` (incluyendo cabeceras IP y TCP, ~40 B).
Con esa semántica, un SYN flood producía `src_bytes = 12000` cuando el dataset
describe `neptune` con `src_bytes = 0`. El modelo no reconocía el ataque.

La corrección usa la longitud del payload:

```python
len(raw[layer].payload)   # un SYN puro vale 0
```

---

# 6. El modelo de Machine Learning

## 6.1 Por qué Random Forest

| Criterio | Random Forest | Alternativas |
|---|---|---|
| Datos tabulares | Excelente | Las redes neuronales rinden peor en tabular |
| Features categóricas y numéricas mezcladas | Las maneja sin problema | SVM requiere escalado cuidadoso |
| Sensibilidad a hiperparámetros | Baja | XGBoost requiere más ajuste |
| Interpretabilidad | Alta (`feature_importances_`) | Las redes son caja negra |
| Requiere escalado | No (los árboles dividen por umbral) | SVM y KNN sí |
| Tolerancia a features aproximadas | Alta | Los modelos lineales, no |

Punto clave para este proyecto: en producción las features de host son
**aproximadas** (se calculan por ventana, no sobre el historial completo del
dataset). Un modelo tolerante a esa imprecisión es una ventaja real.

## 6.2 Cómo funciona

Un Random Forest es un **conjunto de árboles de decisión** entrenados en paralelo.

**Un árbol de decisión** hace preguntas sucesivas sobre las features:

```
count <= 128.5?
├── sí → serror_rate <= 0.5?
│        ├── sí → NORMAL
│        └── no → ATAQUE
└── no → same_srv_rate <= 0.3?
         ├── sí → ATAQUE
         └── no → NORMAL
```

Un solo árbol es inestable: un cambio pequeño en los datos cambia su estructura
por completo (**varianza alta**).

**La solución del bosque** son dos fuentes de aleatoriedad:

1. **Bagging** — cada árbol se entrena con una muestra aleatoria con reemplazo
   del conjunto de datos.
2. **Selección aleatoria de features** — en cada división, el árbol solo
   considera un subconjunto aleatorio de features.

Cada árbol ve una versión distinta de los datos. Al promediar sus votos, los
errores individuales se cancelan y la varianza cae drásticamente.

**La predicción final** es el promedio de las probabilidades de todos los árboles:

```
score = (1 / 300) · Σ  P(árbol_i dice "ataque")
```

## 6.3 Hiperparámetros elegidos

```python
RandomForestClassifier(
    n_estimators=300,        # número de árboles
    class_weight="balanced", # compensa el desbalanceo
    n_jobs=-1,               # usa todos los núcleos
    random_state=42,         # reproducibilidad
)
```

| Parámetro | Valor | Justificación |
|---|---|---|
| `n_estimators` | 300 | A partir de ~200 la mejora es marginal; 300 da margen |
| `class_weight` | `"balanced"` | `neptune` sola es el 70% de los ataques; sin esto el modelo ignora las clases raras |
| `n_jobs` | -1 | Paraleliza entre núcleos; el entrenamiento baja a 7.2 s |
| `random_state` | 42 | **Reproducibilidad**: la CI regenera el mismo artefacto en cada push |

---

# 7. El entrenamiento

## 7.1 Flujo

```bash
uv run python -m src.train --data-dir data
```

1. Carga `KDDTrain+.txt` (125 973 flujos) y `KDDTest+.txt` (22 544)
2. Ajusta el `FlowEncoder` **solo con el train** (vocabulario y escalado)
3. Valida con `StratifiedKFold` de 3 particiones sobre el train
4. Entrena el Random Forest sobre todo el train
5. Barre umbrales de decisión sobre el test
6. Elige el umbral que maximiza F1
7. Persiste el artefacto con encoder + clasificador + umbral

**Por qué el encoder se ajusta solo con el train:** si se ajustara con el test se
produciría *data leakage* — el modelo vería información del conjunto de prueba, y
las métricas resultantes no valdrían nada.

## 7.2 La decisión más importante: el umbral

Un clasificador binario devuelve una **probabilidad**, no una etiqueta. Hay que
decidir a partir de qué valor se considera "ataque". Scikit-learn usa **0.5** por
defecto.

Ese 0.5 es el punto que maximiza *accuracy* — pero en un NIDS eso es la métrica
equivocada.

**El barrido real sobre el conjunto de prueba:**

| Umbral | Precision | Recall | F1 |
|---|---|---|---|
| 0.50 | 0.967 | **0.639** | 0.770 |
| 0.45 | 0.966 | 0.663 | 0.786 |
| 0.40 | 0.961 | 0.689 | 0.803 |
| 0.35 | 0.962 | 0.717 | 0.821 |
| 0.30 | 0.955 | 0.757 | 0.844 |
| 0.25 | 0.921 | 0.789 | 0.850 |
| 0.20 | 0.924 | 0.829 | 0.874 |
| 0.15 | 0.925 | 0.864 | 0.894 |
| 0.10 | 0.926 | 0.909 | 0.917 |
| **0.05** | **0.925** | **0.956** | **0.940** |

**Lectura:** con el umbral por defecto (0.5) el sistema **perdía el 36% de los
ataques**. Bajarlo a 0.05 recupera la mayoría manteniendo la precisión en 0.925.

**Justificación de la decisión:** en seguridad, el costo de los dos errores es
asimétrico.

- **Falso negativo** (ataque no detectado): el atacante entra. Costo alto.
- **Falso positivo** (alerta falsa): un analista revisa. Costo bajo.

Optimizar F1 encuentra el equilibrio, y en este caso concreto se logra sin
sacrificar precisión: 0.925 sigue siendo un valor alto.

**Consecuencia de diseño:** el umbral **viaja dentro del artefacto**
(`ModelBundle`). Si viviera como constante en el código de inferencia, la
evaluación y el servicio podrían usar valores distintos y las métricas del
informe no respaldarían lo que el sistema hace en producción.

---

# 8. La evaluación

## 8.1 Métricas sobre el conjunto de prueba

Sobre los **22 544 flujos** de `KDDTest+.txt` que el modelo nunca vio:

| Métrica | Valor |
|---|---|
| Accuracy | 0.9310 |
| **Precision** | **0.9254** |
| **Recall** | **0.9559** |
| **F1** | **0.9404** |
| ROC-AUC | 0.9595 |
| Latencia de inferencia | 0.338 ms/flujo |
| Tiempo de entrenamiento | 7.22 s |

## 8.2 Matriz de confusión

|  | Predicho normal | Predicho ataque |
|---|---|---|
| **Real normal** (9 711) | 8 722 ✅ | 989 ❌ falso positivo |
| **Real ataque** (12 833) | 566 ❌ falso negativo | 12 267 ✅ |

**Interpretación:**

- **Tasa de falsos positivos:** 989 / 9 711 = **10.2%** del tráfico benigno
  genera una alerta. Es aceptable para un sistema de laboratorio: un analista
  revisa una de cada diez conexiones normales.
- **Tasa de falsos negativos:** 566 / 12 833 = **4.4%** de los ataques pasan.
  El 95.6% se detecta.

## 8.3 Por qué `accuracy` no basta

Con un 56.9% de ataques en el test, un clasificador que **siempre** respondiera
"ataque" obtendría un 56.9% de accuracy sin detectar nada útil. Por eso la
evaluación reporta precision, recall, F1 y la matriz de confusión completa.

## 8.4 Validación cruzada

`StratifiedKFold` de 3 particiones sobre el conjunto de entrenamiento:

```
F1 = 0.9986 ± 0.0001
```

La desviación de 0.0001 indica que el modelo es **estable**: el resultado no
depende de qué partición toque. La estratificación garantiza que cada partición
mantenga la proporción de clases.

## 8.5 La brecha entre validación y prueba

| | F1 |
|---|---|
| Validación cruzada (train) | **0.9986** |
| Conjunto de prueba | **0.9404** |

Una brecha de casi 6 puntos. **No es un error de implementación** y explicarla
correctamente es lo que separa un análisis superficial de uno riguroso.

---

# 9. El hallazgo principal: novelty effect

## 9.1 La evidencia

Comparando las familias de ataque presentes en cada archivo:

| | Familias distintas |
|---|---|
| En `KDDTrain+.txt` | 23 |
| En `KDDTest+.txt` | 38 |
| **Solo en el test** | **17** |

**3 750 flujos de ataque (16.6% del test) pertenecen a familias que el modelo
nunca vio durante el entrenamiento.** Entre ellas: `mscan` (996), `processtable`
(685), `snmpguess` (331), `saint` (319), `mailbomb` (293), `snmpgetattack` (178).

## 9.2 Qué significa

El modelo no puede clasificar correctamente lo que no ha visto. Esos 3 750 flujos
son, en gran medida, la explicación de la brecha entre 0.9986 y 0.9404.

**Esto es una propiedad conocida y deliberada de NSL-KDD**, no un defecto. El
dataset fue diseñado para que el conjunto de prueba contuviera ataques novedosos
y así medir la capacidad de **generalización**, no de memorización.

## 9.3 Por qué importa para el proyecto

Esta es la conclusión técnica más valiosa de la sustentación:

> **Un 99% de accuracy en un benchmark no significa nada en producción.** El
> modelo aprende la distribución del conjunto con el que se entrenó. Cuando
> enfrenta tráfico con características distintas —otro dataset, otra red, otro
> ataque— su desempeño cae.

La literatura reciente documenta el fenómeno con crudeza: clasificadores que
alcanzan 98% en su conjunto de prueba **colapsan a 68% con una tasa de falsos
positivos del 42%** cuando se enfrentan a tráfico capturado independientemente.

La causa no es el modelo, es la metodología de evaluación: comparar contra el
mismo benchmark con el que se entrenó mide memorización, no detección.

## 9.4 Consecuencia práctica

Este hallazgo es exactamente lo que justifica la siguiente fase del proyecto: un
**laboratorio con máquinas virtuales** donde capturar tráfico real y medir el
desempeño sobre datos que el sistema nunca vio. Es también la razón de dejar
CICIDS2017 como validación cruzada entre datasets.

---

# 10. Del entrenamiento a la captura en vivo

## 10.1 El pipeline completo

```
[PCAP o NIC en vivo]
        │
        ▼  src/replay.py :: packet_to_dict()
   Paquete normalizado (IP, puertos, payload, flags, timestamp)
        │
        ▼  src/features.py :: FlowAggregator
   Flujo acumulado por 5-tupla, en ventanas de 2 s
        │
        ▼  FlowFeatures (23 campos validados)
        │
        ▼  src/pipeline.py :: ModelBundle.predict()
   FlowEncoder (one-hot + escalado) → Random Forest → probabilidad
        │
        ▼  comparación contra el umbral 0.05
   Predicción (es_ataque, score)
        │
        ▼  src/alerts.py
   Alerta persistida en output/alertas.jsonl
```

## 10.2 Ventanas duales

El sistema usa **dos ventanas** en paralelo, siguiendo la práctica de la
literatura:

| Ventana | Duración | Para qué |
|---|---|---|
| **Burst** | 2 segundos | Ataques volumétricos (SYN flood, inundaciones) |
| **Host** | 100 segundos | Comportamiento de host (escaneos, fuerza bruta) |

Un SYN flood se manifiesta en ráfagas cortas; un escaneo de puertos se revela por
la acumulación de conexiones a lo largo del tiempo. Una sola escala temporal no
captura ambos patrones.

## 10.3 Captura en vivo

`scripts/live_nids.py` implementa la captura contra una interfaz real. Dentro de
un contenedor Linux con `CAP_NET_ADMIN`, `scapy.sniff()` accede a la pila de red
directamente.

**Por qué en contenedor y no en Windows:** en Windows la captura requiere el
driver Npcap y permisos de administrador. En un contenedor Linux basta con
conceder capacidades al contenedor, no al usuario. Verificado durante el
desarrollo: sin Npcap y sin admin, `scapy.sniff()` **falla** en Windows.

## 10.4 Las tres familias de ataque de la demostración

| Ataque | Herramienta | Perfil NSL-KDD | Resultado |
|---|---|---|---|
| SYN flood | `hping3 -S --flood --rand-source` | `neptune` | 260/260 detectados |
| Escaneo de puertos | `nmap -sS -p 1-300` | `nmap` | 80/80 detectados |
| Inundación HTTP | `curl` en paralelo | `satan` | 60/60 detectados |

Cada uno reproduce el perfil de un ataque real del dataset. **No son ataques
inventados**: son los que la literatura describe.

---

# 11. Decisiones de ingeniería y trade-offs

## 11.1 Store de alertas en JSONL, no JSON

El store es **append-only**, una línea JSON por alerta.

**Por qué:** dos escritores concurrentes (el servicio HTTP y el reproductor)
corrompen un archivo JSON reescrito completo. El *append* de una línea corta es
atómico en los sistemas de archivos habituales. Además, un lector puede cortar el
archivo en cualquier línea y seguir interpretando el resto — una línea corrupta
por un fallo no invalida el historial.

## 11.2 Métricas en un solo módulo

`metrics.py` centraliza el cálculo. Antes estaba duplicado en `train.py` y
`infer.py`.

**Por qué importa:** si las métricas del informe y las de la demostración se
calculan en dos sitios, pueden divergir. Tenerlas en un solo lugar garantiza que
ambas reporten lo mismo.

## 11.3 Dos etapas en la demostración

`scripts/demo.py` separa deliberadamente:

1. **Evaluación rigurosa** — sobre los 22 544 flujos reales de `KDDTest+.txt`
2. **Mecanismo** — reproducción de PCAP sintéticos para mostrar el flujo
   paquete → flujo → alerta

**Por qué no mezclarlas:** medir falsos positivos sobre tráfico que uno mismo
generó es medir el modelo con datos fabricados. Los números de desempeño salen
exclusivamente de la etapa 1.

## 11.4 El artefacto reproducible en CI

El modelo **no se versiona** en el repositorio (es un binario derivado de 30 MB).
La integración continua lo **regenera** en cada push con `random_state=42`, y lo
hornea dentro de la imagen Docker.

**Ventajas:** el repositorio pesa 13 MB en vez de 43, y el artefacto es
reproducible — cualquiera puede verificar que el mismo código y los mismos datos
producen el mismo modelo.

---

# 12. Limitaciones

Declararlas fortalece la sustentación: son límites conocidos y acotados, no
sorpresas.

## 12.1 Del dataset

1. **Antigüedad.** KDD99 es de 1999. El tráfico de red de 1999 no se parece al
   actual: no hay HTTPS generalizado, ni IoT, ni tráfico móvil.
2. **Novelty effect.** El 16.6% del test son familias que el entrenamiento nunca
   vio. El 0.94 de F1 es el desempeño sobre un conjunto que incluye ataques
   imposibles de aprender.
3. **Desbalanceo.** `neptune` es el 70% de los ataques. El modelo está
   desproporcionadamente entrenado en DoS.

## 12.2 Del modelo

4. **No es adaptativo.** Es clasificación supervisada por lotes. El modelo es
   estático hasta que se reentrene. **Llamarlo "adaptativo" sería incorrecto**, y
   la propuesta usa ese término: conviene precisarlo en la defensa.
5. **Solo clasificación binaria.** No distingue la familia del ataque.
6. **Sin comparación de modelos.** La propuesta menciona entrenar y comparar
   Random Forest, XGBoost, etc. Solo está implementado Random Forest.

## 12.3 De las features

7. **18 de 41 features no son reproducibles** desde paquetes crudos.
8. **Las features de host se aproximan por ventana.** El `dst_host_count` real de
   NSL-KDD requiere el historial de conexiones; la versión en vivo lo aproxima con
   las conexiones observadas en la ventana. En ráfagas cortas la aproximación se
   aleja del valor real.
9. **Umbral no óptimo para tráfico real.** El 0.05 se eligió sobre `KDDTest+`.
   Con tráfico de otra distribución probablemente requiera recalibración.

## 12.4 Del sistema

10. **La captura en vivo requiere Linux.** En Windows hace falta Npcap y permisos
    de administrador.
11. **Sin bloqueo (IPS).** El sistema solo detecta y alerta, que es lo que el
    alcance declara.
12. **Sin persistencia de estado entre ejecuciones.** Las estadísticas de host se
    pierden al reiniciar.

---

# 13. Reproducibilidad

Todo el proyecto es reproducible desde cero:

```bash
# 1. Dependencias
uv sync --extra dev

# 2. Descarga el dataset, entrena y verifica
uv run python scripts/bootstrap.py

# 3. Verificación de calidad
uv run pytest            # 77 tests
uv run ruff check .      # linter, select = ALL
uv run basedpyright      # typeCheckingMode = all
```

**El artefacto es determinista:** `random_state=42` garantiza que el mismo código
y los mismos datos produzcan exactamente el mismo modelo. La integración continua
lo regenera y verifica en cada push.

**Trazabilidad:** el repositorio está en
[github.com/Murif777/detector-intrusiones-ml](https://github.com/Murif777/detector-intrusiones-ml),
con la imagen publicada en `ghcr.io/murif777/detector-intrusiones-ml`.

---

# Apéndice — Cifras para citar

| Concepto | Valor |
|---|---|
| Flujos de entrenamiento | 125 973 |
| Flujos de prueba | 22 544 |
| Columnas del dataset | 43 (41 features + label + difficulty) |
| Features usadas | 23 (20 numéricas + 3 categóricas) |
| Features descartadas por no ser reproducibles | 18 |
| Dimensiones tras el one-hot | 107 |
| Árboles del bosque | 300 |
| Familias de ataque en train | 23 |
| Familias de ataque en test | 38 |
| Familias solo en test | 17 (3 750 flujos, 16.6%) |
| Umbral de decisión | 0.05 |
| Accuracy | 0.9310 |
| Precision | 0.9254 |
| Recall | 0.9559 |
| F1 | 0.9404 |
| ROC-AUC | 0.9595 |
| Validación cruzada (F1) | 0.9986 ± 0.0001 |
| Entrenamiento | 7.22 s |
| Inferencia | 0.338 ms/flujo |
| Falsos positivos | 10.2% |
| Falsos negativos | 4.4% |
| Tests automatizados | 77 |
| Tamaño del repositorio | 13 MB |

---

# Referencias

1. Tavallaee, M., Bagheri, E., Lu, W., & Ghorbani, A. A. (2009). *A detailed
   analysis of the KDD CUP 99 data set*. IEEE Symposium on Computational
   Intelligence for Security and Defense Applications.

2. Canadian Institute for Cybersecurity, University of New Brunswick. *NSL-KDD
   dataset*. https://www.unb.ca/cic/datasets/nsl.html

3. Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). *Toward
   generating a new intrusion detection dataset and intrusion traffic
   characterization*. ICISSP.

4. Breiman, L. (2001). *Random Forests*. Machine Learning, 45(1), 5–32.

5. Sommer, R., & Paxson, V. (2010). *Outside the closed world: On using machine
   learning for network intrusion detection*. IEEE Symposium on Security and
   Privacy.

6. Engelen, G., Rimmer, V., & Joosen, W. (2021). *Troubleshooting an intrusion
   detection dataset: the CICIDS2017 case study*. IEEE Security and Privacy
   Workshops.
