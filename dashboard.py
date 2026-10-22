"""Centro de operaciones del NIDS.

    uv run streamlit run dashboard.py

Panel de control en vivo del detector: estado, feed de detecciones, analitica
de las alertas, logs del contenedor y disparo de ataques desde la propia pagina.

Diseno: sala de control de seguridad. Fondo azul-negro profundo (no negro
plano), tipografia IBM Plex para la interfaz y IBM Plex Mono para todo lo que
es dato. El rojo aparece UNICAMENTE para lo malicioso, de modo que el ojo
vaya directo a lo que importa sin tener que leer la pantalla.
"""
from __future__ import annotations

import contextlib
import json
from datetime import datetime
from typing import Final

import altair as alt
import pandas as pd
import streamlit as st

from src.alerts import ALERTS_PATH, read_alerts
from src.docker_control import ATTACKS, DockerControl
from src.pipeline import METRICS_PATH, PIPELINE_PATH
from src.schema import Alert

REFRESH_SECONDS: Final[str] = "1s"
REFRESH_EVERY_S: Final[float] = 1.0
MAX_FEED: Final[int] = 12
MAX_TABLE: Final[int] = 500
LOG_LINES: Final[int] = 120

#: Umbral por defecto del artefacto. Solo se usa como referencia visual cuando
#: no se puede leer `metrics.json`; el valor real vive en el modelo.
ATTACK_THRESHOLD: Final[float] = 0.05
#: Posiciones de la hora dentro de un timestamp ISO.
TIME_SLICE_START: Final[int] = 11
TIME_SLICE_END: Final[int] = 19
#: Unidad de conversion de bytes.
BYTES_PER_UNIT: Final[int] = 1024

#: Paleta. El rojo es exclusivamente para lo malicioso.
CRITICAL: Final[str] = "#FF4757"
OK: Final[str] = "#2ED3A0"
ACCENT: Final[str] = "#4C9AFF"
WARN: Final[str] = "#FFB84D"

# ── Tokens de diseno ────────────────────────────────────────────
# Un solo acento para lo malicioso. El resto es estructura.
CSS: Final[str] = """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap');

:root {
  --bg:        #0A0E13;
  --surface:   #121922;
  --surface-2: #1A232E;
  --border:    #24303C;
  --text:      #E6EDF3;
  --dim:       #93A4B1;
  --faint:     #5D6E7C;
  --critical:  #FF4757;
  --ok:        #2ED3A0;
  --accent:    #4C9AFF;
  --warn:      #FFB84D;
}

.stApp { background: var(--bg); }
html, body, [class*="css"] { font-family: 'IBM Plex Sans', sans-serif; color: var(--text); }
code, pre, [data-testid="stCode"] { font-family: 'IBM Plex Mono', monospace !important; }

h1, h2, h3 { font-family: 'IBM Plex Sans', sans-serif; letter-spacing: -0.02em; }
h1 { font-size: 1.65rem; font-weight: 700; }
h2 { font-size: 1.05rem; font-weight: 600; color: var(--text); }
h3 { font-size: .92rem; font-weight: 600; color: var(--dim); }

/* Barra superior: una sola banda, no tarjetas flotantes */
.nids-topbar {
  display: flex; align-items: center; gap: 1.4rem; flex-wrap: wrap;
  padding: .85rem 1.1rem; margin-bottom: 1.1rem;
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px;
}
.nids-brand { font-family: 'IBM Plex Mono', monospace; font-weight: 600;
  font-size: 1.05rem; letter-spacing: .02em; }
.nids-dot { width: 9px; height: 9px; border-radius: 50%; display: inline-block; }
.nids-pill {
  font-family: 'IBM Plex Mono', monospace; font-size: .72rem;
  padding: .22rem .6rem; border-radius: 999px;
  border: 1px solid var(--border); color: var(--dim);
}
.nids-pill.live  { color: var(--ok);     border-color: var(--ok);     }
.nids-pill.down  { color: var(--critical); border-color: var(--critical); }
.nids-pill.warn  { color: var(--warn);   border-color: var(--warn); }
.nids-spacer { flex: 1 1 auto; }

/* Tira de indicadores: plano, sin sombras ni esquinas redundantes */
.nids-strip { display: flex; gap: 0; margin-bottom: 1.1rem;
  border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
.nids-stat { flex: 1 1 0; padding: .8rem 1rem; background: var(--surface);
  border-right: 1px solid var(--border); }
.nids-stat:last-child { border-right: none; }
.nids-stat .k { font-family: 'IBM Plex Mono', monospace; font-size: .68rem;
  color: var(--faint); text-transform: uppercase; letter-spacing: .08em; }
.nids-stat .v { font-family: 'IBM Plex Mono', monospace; font-size: 1.5rem;
  font-weight: 600; line-height: 1.25; margin-top: .15rem; }
.nids-stat .v.crit { color: var(--critical); }
.nids-stat .v.ok   { color: var(--ok); }

/* Feed en vivo: el elemento memorable de la pagina */
.nids-feed { border: 1px solid var(--border); border-radius: 10px;
  background: var(--surface); overflow-x: hidden; overflow-y: auto;
  max-height: 320px; }
.nids-feed-row { display: flex; align-items: center; gap: .8rem;
  padding: .42rem .9rem; border-bottom: 1px solid var(--border);
  font-family: 'IBM Plex Mono', monospace; font-size: .78rem; }
.nids-feed-row:last-child { border-bottom: none; }
.nids-feed-row .t { color: var(--faint); flex: 0 0 auto; }
.nids-feed-row .sc { flex: 0 0 auto; font-weight: 600; }
.nids-feed-row .sc.crit { color: var(--critical); }
.nids-feed-row .sc.ok   { color: var(--ok); }
.nids-feed-row .vd { flex: 0 0 auto; font-size: .66rem; font-weight: 700;
  letter-spacing: .07em; padding: .12rem .5rem; border-radius: 999px; }
.nids-feed-row .vd.atk { color: #fff; background: var(--critical); }
.nids-feed-row .vd.okm { color: #fff; background: var(--ok); }
.nids-feed-row .meta { color: var(--dim); overflow: hidden; text-overflow: ellipsis;
  white-space: nowrap; }
.nids-bar { flex: 0 0 70px; height: 5px; background: var(--surface-2);
  border-radius: 3px; overflow: hidden; }
.nids-bar > i { display: block; height: 100%; border-radius: 3px; }

/* Terminal de logs */
.nids-term { background: #05080B; border: 1px solid var(--border); border-radius: 10px;
  padding: .8rem .95rem; font-family: 'IBM Plex Mono', monospace; font-size: .74rem;
  line-height: 1.55; color: #B7C6D2; max-height: 320px; overflow-y: auto; }
.nids-term .alert { color: var(--critical); }
.nids-term .attack { color: var(--warn); }
.nids-term .sys { color: var(--accent); }

/* Controles de ataque */
.nids-ctl { border: 1px solid var(--border); border-radius: 10px;
  background: var(--surface); padding: .9rem 1rem; }
.nids-ctl .row { display: flex; align-items: center; justify-content: space-between;
  padding: .5rem 0; border-bottom: 1px solid var(--border); }
.nids-ctl .row:last-of-type { border-bottom: none; }
.nids-ctl .name { font-family: 'IBM Plex Mono', monospace; font-size: .8rem; }
.nids-ctl .desc { font-size: .74rem; color: var(--faint); }

.stButton > button {
  background: var(--surface-2); color: var(--text);
  border: 1px solid var(--border); border-radius: 7px;
  font-family: 'IBM Plex Mono', monospace; font-size: .76rem; font-weight: 500;
  padding: .34rem .7rem; transition: border-color .12s, background .12s;
}
.stButton > button:hover { border-color: var(--accent); color: #fff;
  background: #202B38; }
.stButton > button:focus-visible { outline: 2px solid var(--accent);
  outline-offset: 2px; }
.stButton > button[kind="primary"] { background: #2A4B7C; border-color: #3D6FB0; }
.stButton > button[kind="primary"]:hover { background: #32588F; }

div[data-testid="stMetricValue"] { font-family: 'IBM Plex Mono', monospace; }
div[data-testid="stMetricLabel"] { font-family: 'IBM Plex Mono', monospace;
  font-size: .68rem; color: var(--faint); }
[data-testid="stDataFrame"] { border: 1px solid var(--border); border-radius: 8px; }
hr { border-color: var(--border); }
</style>
"""

ATTACK_DESCRIPTIONS: Final[dict[str, str]] = {
    "1": "SYN sin respuesta, muchos puertos origen",
    "2": "Barrido de puertos contra la victima",
    "3": "POST grandes con respuesta de la victima",
    "all": "Los tres, espaciados en el tiempo",
    "normal": "Solo GET legitimos, para ver el falso positivo",
}

SCORE_BINS: Final[list[float]] = [0.0, 0.05, 0.1, 0.2, 0.3, 0.5, 0.7, 0.9, 1.01]


# ── Utilidades ─────────────────────────────────────────────────
def _alerts_frame(alerts: list[Alert]) -> pd.DataFrame:
    """Convierte las alertas a un DataFrame listo para graficar."""
    rows = [
        {
            "ts": a.ts,
            "hora": _local_hour(a.ts),
            "label": a.label,
            "score": a.score,
            "proto": a.flow.protocol_type,
            "servicio": a.flow.service,
            "flag": a.flow.flag,
            "src_bytes": a.flow.src_bytes,
            "dst_bytes": a.flow.dst_bytes,
            "paquetes": a.flow.count,
            "serror": a.flow.serror_rate,
        }
        for a in alerts
    ]
    return pd.DataFrame(rows)


def _local_hour(value: str) -> str:
    """Extrae HH:MM:SS de un timestamp ISO, o la hora local si se puede."""
    try:
        return datetime.fromisoformat(value).strftime("%H:%M:%S")
    except ValueError:
        return value[11:19] if len(value) >= TIME_SLICE_END else value


def _score_color(score: float) -> str:
    """Verde si es normal, rojo si es malicioso."""
    return CRITICAL if score >= ATTACK_THRESHOLD else OK


def _human_bytes(value: float) -> str:
    """Bytes en unidades legibles."""
    for unit in ("B", "KB", "MB", "GB"):
        if value < BYTES_PER_UNIT:
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= BYTES_PER_UNIT
    return f"{value:.1f} TB"


# ── Componentes ─────────────────────────────────────────────────
def _topbar(control: DockerControl, alerts: list[Alert]) -> None:
    """Banda superior: identidad, estado del detector y umbral activo."""
    status = control.detector_status()
    attacks = sum(1 for a in alerts if a.label == "ataque")
    if not control.available:
        state, color, word = "down", CRITICAL, "SIN DOCKER"
    elif status.running:
        state, color, word = "live", OK, "EN VIVO"
    else:
        state, color, word = "warn", WARN, "DETENIDO"

    model = "sin modelo"
    if PIPELINE_PATH.exists():
        model = PIPELINE_PATH.parent.name
    umbral = f"{ATTACK_THRESHOLD:.2f}"
    if METRICS_PATH.exists():
        with contextlib.suppress(OSError, ValueError):
            datos = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
            umbral = f"{float(datos.get('threshold', ATTACK_THRESHOLD)):.2f}"

    st.markdown(
        f"""
        <div class="nids-topbar">
          <span class="nids-brand">NIDS<span style="color:var(--faint)">/</span>ML</span>
          <span class="nids-pill {state}"><span class="nids-dot" style="background:{color}"></span>
            &nbsp;{word}</span>
          <span class="nids-pill">{attacks} alertas</span>
          <span class="nids-pill">umbral {umbral}</span>
          <span class="nids-pill">{model}</span>
          <span class="nids-spacer"></span>
          <span class="nids-pill">{len(alerts)} eventos registrados</span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _stat_strip(alerts: list[Alert]) -> None:
    """Tira de indicadores: cuatro cifras, sin tarjetas redundantes."""
    attacks = sum(1 for a in alerts if a.label == "ataque")
    mean = sum(a.score for a in alerts) / len(alerts) if alerts else 0.0
    bytes_total = sum(a.flow.src_bytes + a.flow.dst_bytes for a in alerts)
    pico = max((a.score for a in alerts), default=0.0)
    clase_pico = "crit" if pico >= ATTACK_THRESHOLD else ""

    st.markdown(
        f"""
        <div class="nids-strip">
          <div class="nids-stat">
            <div class="k">eventos</div><div class="v">{len(alerts)}</div></div>
          <div class="nids-stat">
            <div class="k">maliciosos</div><div class="v crit">{attacks}</div></div>
          <div class="nids-stat">
            <div class="k">score medio</div><div class="v">{mean:.3f}</div></div>
          <div class="nids-stat">
            <div class="k">score maximo</div>
            <div class="v {clase_pico}">{pico:.3f}</div></div>
          <div class="nids-stat">
            <div class="k">volumen</div><div class="v">{_human_bytes(bytes_total)}</div></div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _feed(alerts: list[Alert]) -> None:
    """Feed en vivo: las detecciones mas recientes con barra de score."""
    st.markdown("#### Detecciones en vivo")
    if not alerts:
        st.html(
            '<div class="nids-feed"><div class="nids-feed-row">'
            '<span class="meta">Sin eventos todavia. Lanza un ataque desde el panel '
            "izquierdo.</span>"
            "</div></div>",
        )
        return

    rows = []
    for alert in reversed(alerts[-MAX_FEED:]):
        crit = alert.label == "ataque"
        color = _score_color(alert.score)
        pct = min(100.0, alert.score * 100)
        veredicto = "ATAQUE" if crit else "NORMAL"
        rows.append(
            '<div class="nids-feed-row">'
            f'<span class="vd {"atk" if crit else "okm"}">{veredicto}</span>'
            f'<span class="t">{_local_hour(alert.ts)}</span>'
            f'<span class="sc {"crit" if crit else "ok"}">{alert.score:.3f}</span>'
            f'<span class="nids-bar"><i style="width:{pct:.0f}%;background:{color}"></i></span>'
            f'<span class="meta">{alert.flow.protocol_type}/{alert.flow.service}'
            f'&nbsp;flag={alert.flow.flag} &nbsp;pkts={alert.flow.count}'
            f'&nbsp;serror={alert.flow.serror_rate:.2f}</span>'
            '</div>'
        )
    # st.html en vez de st.markdown: el procesador Markdown convierte las lineas
    # indentadas del template en bloques de codigo literal y se veia el HTML.
    st.html(f'<div class="nids-feed">{"".join(rows)}</div>')


def _charts(frame: pd.DataFrame) -> None:
    """Analitica: distribucion de score, linea de tiempo y ranking de flags."""
    if frame.empty:
        st.info("Sin datos para graficar todavia.")
        return

    left, right = st.columns([1, 1])

    with left:
        st.markdown("#### Distribucion del score")
        hist = (
            alt.Chart(frame)
            .mark_bar(color="#4C9AFF", cornerRadiusTopLeft=2, cornerRadiusTopRight=2)
            .encode(
                x=alt.X("score:Q", bin=alt.Bin(maxbins=24), title=None),
                y=alt.Y("count()", title=None),
                tooltip=["score:Q", "count()"],
            )
            .properties(height=210)
        )
        st.altair_chart(hist, use_container_width=True)

    with right:
        st.markdown("#### Eventos por minuto")
        por_minuto = (
            frame.assign(minuto=pd.to_datetime(frame["ts"]).dt.floor("min"))
            .groupby("minuto")
            .agg(total=("score", "size"), maliciosos=("label", lambda s: (s == "ataque").sum()))
            .reset_index()
        )
        area = (
            alt.Chart(por_minuto)
            .mark_area(color="#FF4757", opacity=0.75, interpolate="monotone")
            .encode(
                x=alt.X("minuto:T", title=None),
                y=alt.Y("maliciosos:Q", title=None),
                tooltip=["minuto:T", "maliciosos:Q"],
            )
            .properties(height=210)
        )
        st.altair_chart(area, use_container_width=True)

    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("#### Flags de TCP")
        flags = frame["flag"].value_counts().rename_axis("flag").reset_index(name="n")
        st.altair_chart(
            alt.Chart(flags)
            .mark_bar(color="#FFB84D", cornerRadiusTopRight=3)
            .encode(y=alt.Y("flag:N", sort="-x", title=None), x=alt.X("n:Q", title=None))
            .properties(height=190),
            use_container_width=True,
        )
    with c2:
        st.markdown("#### Servicios atacados")
        servicios = frame["servicio"].value_counts().rename_axis("servicio").reset_index(name="n")
        st.altair_chart(
            alt.Chart(servicios)
            .mark_bar(color="#4C9AFF", cornerRadiusTopRight=3)
            .encode(y=alt.Y("servicio:N", sort="-x", title=None), x=alt.X("n:Q", title=None))
            .properties(height=190),
            use_container_width=True,
        )
    with c3:
        st.markdown("#### Bytes por direccion")
        st.altair_chart(
            alt.Chart(frame)
            .mark_bar(color="#2ED3A0", cornerRadiusTopRight=3)
            .encode(
                y=alt.Y("servicio:N", sort="-x", title=None),
                x=alt.X("sum(src_bytes):Q", title=None),
                tooltip=["servicio:N", "sum(src_bytes):Q", "sum(dst_bytes):Q"],
            )
            .properties(height=190),
            use_container_width=True,
        )


def _table(frame: pd.DataFrame) -> None:
    """Tabla completa de alertas, con filtro por veredicto."""
    st.markdown("#### Registro de alertas")
    if frame.empty:
        st.info("Sin alertas registradas.")
        return
    c1, c2 = st.columns([1, 3])
    with c1:
        veredicto = st.selectbox("Veredicto", ["todos", "ataque", "normal"], key="filtro_veredicto")
    with c2:
        texto = st.text_input(
            "Buscar", placeholder="servicio, flag o protocolo", key="filtro_texto"
        )

    filtrado = frame
    if veredicto != "todos":
        filtrado = filtrado[filtrado["label"] == veredicto]
    if texto:
        patron = texto.lower()
        filtrado = filtrado[
            filtrado["servicio"].str.lower().str.contains(patron, regex=False)
            | filtrado["flag"].str.lower().str.contains(patron, regex=False)
            | filtrado["proto"].str.lower().str.contains(patron, regex=False)
        ]

    st.dataframe(
        filtrado.tail(MAX_TABLE),
        use_container_width=True,
        hide_index=True,
        column_config={
            "ts": st.column_config.TextColumn("timestamp", width="small"),
            "hora": st.column_config.TextColumn("hora", width="small"),
            "label": st.column_config.TextColumn("veredicto", width="small"),
            "score": st.column_config.ProgressColumn(
                "score", min_value=0.0, max_value=1.0, format="%.3f", width="small"
            ),
            "proto": st.column_config.TextColumn("proto", width="small"),
            "servicio": st.column_config.TextColumn("servicio", width="small"),
            "flag": st.column_config.TextColumn("flag", width="small"),
            "src_bytes": st.column_config.NumberColumn("bytes origen", format="%d"),
            "dst_bytes": st.column_config.NumberColumn("bytes destino", format="%d"),
            "paquetes": st.column_config.NumberColumn("paquetes", format="%d"),
            "serror": st.column_config.NumberColumn("serror", format="%.2f"),
        },
    )
    st.caption(f"{len(filtrado)} de {len(frame)} eventos")


def _logs(control: DockerControl) -> None:
    """Consola del detector en vivo."""
    st.markdown("#### Consola del detector")
    lineas = control.tail_logs(LOG_LINES)
    if not lineas:
        st.markdown(
            '<div class="nids-term">'
            "<span class='sys'>[sin logs]</span> "
            "El contenedor detector no esta corriendo, o no hay acceso al socket de Docker."
            "</div>",
            unsafe_allow_html=True,
        )
        return
    pintadas = []
    for linea in lineas[-LOG_LINES:]:
        clase = "sys"
        if "ALERTA" in linea or "ATAQUE" in linea:
            clase = "alert"
        elif ">>>" in linea or "ataque" in linea.lower():
            clase = "attack"
        pintadas.append(f"<span class='{clase}'>{_escape(linea)}</span>")
    st.markdown(
        f'<div class="nids-term">{"<br>".join(pintadas)}</div>', unsafe_allow_html=True
    )


def _escape(text: str) -> str:
    """Escapa HTML para insertar texto de logs sin romper el markup."""
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )


def _controls(control: DockerControl) -> None:
    """Panel de control: dispara ataques desde la web.

    Los botones se dibujan siempre para que la capacidad sea visible. Sin acceso
    al socket de Docker quedan deshabilitados con una explicacion, en vez de
    ocultar la funcion por completo.
    """
    st.markdown("#### Control de ataques")
    if not control.available:
        st.caption(
            "Sin acceso al socket de Docker. Monta /var/run/docker.sock en el "
            "servicio dashboard para habilitar el disparo."
        )

    for codigo, nombre in ATTACKS:
        col_b, col_t = st.columns([1, 3])
        with col_b:
            if st.button(
                nombre,
                key=f"btn_{codigo}",
                use_container_width=True,
                disabled=not control.available,
            ):
                resultado = control.launch_attack(codigo)
                if resultado.ok:
                    st.toast(resultado.message)
                else:
                    st.error(resultado.message)
        with col_t:
            st.markdown(
                f'<div class="nids-ctl"><div class="row"><span class="name">{nombre}</span>'
                f'<span class="desc">{ATTACK_DESCRIPTIONS.get(codigo, "")}</span></div></div>',
                unsafe_allow_html=True,
            )


def _containers(control: DockerControl) -> None:
    """Estado de los contenedores del laboratorio."""
    contenedores = control.recent_containers()
    if not contenedores:
        return
    st.markdown("#### Contenedores")
    st.dataframe(
        contenedores, use_container_width=True, hide_index=True,
        column_config={
            "nombre": st.column_config.TextColumn("nombre", width="medium"),
            "estado": st.column_config.TextColumn("estado", width="small"),
            "imagen": st.column_config.TextColumn("imagen", width="large"),
        },
    )


# ── Arranque ────────────────────────────────────────────────────
st.set_page_config(
    page_title="NIDS-ML - Centro de operaciones",
    page_icon="🛰️",
    layout="wide",
    initial_sidebar_state="collapsed",
)
st.markdown(CSS, unsafe_allow_html=True)

control = DockerControl()


@st.fragment(run_every=REFRESH_EVERY_S)
def _live(control: DockerControl) -> None:
    """Todo lo que cambia en vivo: el fragmento se reejecuta solo cada 1 s."""
    alerts = read_alerts(ALERTS_PATH)
    frame = _alerts_frame(alerts)

    _topbar(control, alerts)
    _stat_strip(alerts)

    col_ctrl, col_feed = st.columns([1, 2])

    with col_ctrl:
        _controls(control)

    with col_feed:
        _feed(alerts)

    _charts(frame)

    _tabla = st.container()
    with _tabla:
        _table(frame)

    st.divider()
    col_logs, col_state = st.columns([3, 1])
    with col_logs:
        _logs(control)
    with col_state:
        _containers(control)


_live(control)

st.caption(
    f"Store: {ALERTS_PATH} · el panel se refresca cada {REFRESH_SECONDS} · "
    "los botones lanzan el contenedor atacante contra la victima del laboratorio."
)
