"""NIDS-ML: deteccion de intrusiones basada en ML sobre trafico de red en tiempo real.

Capas:
  schema   contrato de features (Pydantic v2), fuente de verdad train<->live
  dataset  carga NSL-KDD + armonizacion al contrato
  features agregador paquetes -> flujos, el puente hacia el mundo live
  pipeline artefacto unico: FlowEncoder + clasificador, serializado junto
  train    CLI H1, entrena y persiste
  replay   CLI H2, PCAP/NIC -> flujos -> prediccion -> alerta
  api      FastAPI, unica superficie HTTP
  alerts   store JSONL append-only
"""

__version__ = "0.1.0"
