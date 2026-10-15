# NIDS-ML — Plan detallado (MVP laboratorio)

> Tema: SEGURIDAD EN LAS REDES — Sistema de detección de intrusiones basado en ML para monitoreo de tráfico en tiempo real (NIDS)
> Estado: aprobado para implementación. Fecha: 2026-10-14
> Directorio: `C:\Users\farid\Desktop\Proyectos\Proyecto seguridad`

## 1. Veredicto

Sí, viable. Alcance de la propuesta (INCLUYE / NO INCLUYE) correcto para proyecto final.
Se arranca ya con MVP en 4 hitos. Decisiones tomadas: dataset base NSL-KDD, entorno H1-H2 Windows local, H3 lab VMs.

## 2. Arquitectura aterrizada

```
[Replay PCAP / NIC live] -> FlowAggregator (ventanas duales: 2s burst + 100s host)
-> FlowFeatures (Pydantic, 24 features) -> pipeline.joblib [FlowEncoder + RandomForest]
-> FastAPI /predict | replay CLI -> alertas.jsonl -> Dashboard Streamlit
```

**Punto crítico resuelto**: el dataset entrena con features por flujo, Scapy captura paquetes sueltos. La solucion es que `FlowEncoder` (el one-hot + el scaler) viva *dentro* del pipeline serializado, de modo que `predict()` recibe flujos crudos en ambos lados. No existe una segunda implementacion del encoding que pueda divergir: la paridad es estructural. `tests/test_parity.py` verifica el invariante comparando vectores campo por campo.

Corrección de discurso: supervisado batch NO es "adaptativo", es estático hasta reentrenar offline.

Features MVP (24): 21 numericas + 3 categoricas (`protocol_type`, `service`, `flag`).
Las 18 restantes de NSL-KDD no son derivables de paquetes crudos, quedan en 0 y se documentan en `src/dataset.py::UNSUPPORTED_BY_LIVE`.

## 3. Stack

Gestor de paquetes: `uv` (no pip). Toolchain: `basedpyright` (`typeCheckingMode=all`), `ruff` (`select=ALL`), `pytest`.

Runtime: `scikit-learn, polars, numpy, joblib, pydantic v2, typer, rich, fastapi, uvicorn, streamlit, scapy`

Descartado: `xgboost`/`lightgbm` (RF basta para el baseline y tolera mejor el ruido de features aproximadas en live), `cicflowmeter` (feature vocabulary incompatible con NSL-KDD; el agregador propio resuelve el problema y se documenta el tradeoff).

## 4. Hitos y criterios de aceptación

### H0 Setup — COMPLETADO
- Estructura `data/ src/ models/ tests/ scripts/ output/` + `pyproject.toml` (uv, basedpyright all, ruff ALL, pytest)
- Módulos `schema / dataset / features / pipeline / train / replay / api / alerts / dashboard`
- Aceptación cumplida: `ruff check` limpio, `basedpyright` 0 errores, 28 tests verdes

### H1 Baseline offline — CODE COMPLETO, falta dataset real
- `src/train.py`: RF (300 arboles, `class_weight=balanced`), CV 3 folds, accuracy/precision/recall/F1/ROC-AUC + matriz de confusión, latencia por flujo
- Artefacto único `models/pipeline.joblib` (FlowEncoder + clasificador juntos) → **la paridad de features es estructural, no convencional**
- `tests/test_parity.py` (7 tests) es el guardian de ese invariante
- Verificado end-to-end con datos sintéticos: 28 features, 0.41 ms/flujo
- **PENDIENTE**: descargar NSL-KDD real y reentrenar. Hasta entonces las métricas no son evidencia.

### H2 Simulación "tiempo real" — VERIFICADO END-TO-END
- `src/replay.py`: PCAP → agregador (ventanas duales 2s burst / 100s host) → predicción → alerta JSONL
- Ventanas duales siguiendo la literatura: 2s para ataques volumétricos, 100s para comportamiento de host
- **Resultado verificado**: `scripts/make_demo_pcap.py` genera 290 paquetes (200 SYN flood + 90 HTTP normal) → replay detecta 201 ataques, `flag=S0`, `serror=1.00`, 0 falsos positivos sobre el tráfico normal
- API verificada: `/health`, `/predict` (503 sin modelo, 200 con modelo), `/alerts`, `/alerts/recent`

### H3 Live lab + evaluación — PENDIENTE (requiere VMs)
- Lab: Kali (atacante: nmap, hydra, hping3 SYN flood) + Ubuntu (víctima/NIDS)
- **Hallazgo de Windows**: leer PCAP funciona sin Npcap (scapy cae a lector pure-python), pero `sniff()` en vivo NO. Requiere Npcap + admin, o hacer el lab en VMs Linux.
- Aceptación: detecta 3/3 con FP <15%

## 5. Fuera de MVP (no tocar)
Bloqueo/IPS, multi-protocolo avanzado, integración SIEM/empresarial, tuning DL.

## 6. Métricas para el informe
Precision, Recall, F1, ROC-AUC + matriz confusión + latencia inferencia + tasa FP en lab. F1 solo no basta con desbalanceo.

## 7. Riesgos
1. Feature parity train vs live -> mitigado con agregador propio + subset 25 features.
2. CICIDS2017 pesado/sucio -> mitigado empezando NSL-KDD, CICIDS solo Tuesday después.
3. Permisos captura Windows -> mitigado con replay primero, VMs después.
