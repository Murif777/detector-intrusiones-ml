# Demo en vivo — arquitectura y por qué funciona

```bash
docker compose up --build
```

---

## Topología

```
                    red nidsnet (bridge)
   ┌──────────────────────────────────────────────┐
   │                                              │
   │   victim            nids                     │
   │   nginx:alpine      python + scapy           │
   │   10.x.x.x:80       CAP_NET_ADMIN            │
   │        ▲            captura en eth0          │
   │        │                 ▲                   │
   │        │                 │ MISMA eth0        │
   │        │            attacker                 │
   │        │            hping3 / nmap            │
   │        └─────────────────┘                   │
   │            network_mode: service:nids        │
   └──────────────────────────────────────────────┘
```

---

## Por qué el atacante comparte el netns del NIDS

Esta es la decisión de diseño que hace que la demo funcione, y conviene
entenderla porque es la pregunta técnica más probable del jurado.

**El problema**: un bridge de Docker reenvía el tráfico **únicamente al puerto
destino**. Es un switch, no un hub. Si el atacante y el NIDS fueran
contenedores hermanos, el NIDS **no vería** los paquetes dirigidos a la víctima:
el bridge los entregaría solo a la víctima.

Poner la interfaz en modo promiscuo **tampoco basta** en un bridge moderno,
porque el filtrado ocurre en el kernel del host, antes de llegar a la interfaz
del contenedor.

**La solución**: `network_mode: "service:nids"` en el servicio `attacker` hace
que el atacante **comparta el espacio de nombres de red del NIDS**. Desde el
punto de vista del kernel, son el mismo host. Los paquetes del atacante salen
por la misma `eth0`, y el NIDS los captura porque es su propia interfaz.

No hay que reconfigurar bridges ni activar promiscuidad. Funciona siempre.

**Alternativas que se descartaron**:

| Alternativa | Por qué no |
|---|---|
| NIDS como router entre dos redes | Correcto pero mucho más complejo: dos interfaces, IP forwarding, rutas. Riesgo innecesario en una demo. |
| `--privileged` + promiscuo | No resuelve el filtrado del bridge, y `privileged` es mala práctica. |
| Modo `host` | El NIDS vería el tráfico de Windows, no el del ataque. Impredecible. |
| El NIDS se ataca a sí mismo | Funciona, pero es artificial y el jurado lo nota. |

---

## Por qué Linux y no Windows

`scapy.sniff()` necesita una pila de red real con permisos de captura.

| | Linux (contenedor) | Windows (host) |
|---|---|---|
| Captura en vivo | `CAP_NET_ADMIN` | Npcap + admin |
| Instalación | `docker compose up` | driver + permisos |
| Portable a otro PC | sí | depende del driver |

Verificado en el PC de desarrollo: **sin admin y sin Npcap**, `scapy.sniff()`
falla en Windows. Dentro del contenedor funciona porque las capacidades se
conceden al contenedor, no al usuario.

---

## Qué lanza el ataque

`docker/attack.sh`, tres familias espaciadas en el tiempo (el NIDS clasifica por
ventanas de 2 s, así que cada ataque debe caer en ventanas distintas):

| # | Ataque | Herramienta | Perfil NSL-KDD |
|---|---|---|---|
| 1 | SYN flood | `hping3 -S -c 400 -i u2000 --rand-source` | `neptune` |
| 2 | Escaneo de puertos | `nmap -sS -p 1-300` | `nmap` |
| 3 | Inundación HTTP | `curl` en paralelo con POST de 800 B | `satan` |

Cada uno corresponde a un perfil real que el modelo aprendió. No son ataques
inventados: son los que el dataset describe.

---

## Cómo interpretar la salida

Del contenedor `nids-detector`:

```
ALERTA score=0.797 tcp/http flag=S0 src_bytes=0 serror=1.00
       └── prob.  └── protocolo/servicio  └─ estado TCP
```

- `flag=S0` → SYN sin respuesta (nadie contesta: típico de DoS o escaneo)
- `serror_rate=1.00` → el 100% de los intentos falló
- `score` → probabilidad de ataque según el modelo

Al terminar:

```
Resumen en vivo (90s)
  paquetes capturados   1 2xx
  flujos analizados     xxx
  alertas emitidas      xxx
  tasa de alerta        xx%
```

---

## Problemas comunes

| Síntoma | Causa | Solución |
|---|---|---|
| `Modelo no entrenado` | falta `models/pipeline.joblib` | `uv run python -m src.train --data-dir data` |
| El NIDS no ve nada | el atacante no comparte el netns | verifica `network_mode: "service:nids"` |
| `permission denied` al capturar | faltan capacidades | revisa `cap_add: [NET_ADMIN, NET_RAW]` |
| Docker no arranca | Docker Desktop apagado | ábrelo y espera el ícono verde |
| El ataque no se detecta | demasiado corto para la ventana | sube `NIDS_WARMUP` o `--duration` |

---

## Verificar antes de presentar

```bash
docker compose config     # valida el YAML sin arrancar nada
docker compose up --build # ensayo completo
```

Corre `docker compose config` la víspera. Si sale sin error, la configuración
está bien y solo queda probar los contenedores.

---

## Sin Docker: el respaldo

```bash
uv run python scripts/demo.py
```

Evalúa sobre datos reales y reproduce los PCAP. **No necesita Docker, ni admin,
ni drivers.** Si algo falla en el salón, esto responde siempre.
