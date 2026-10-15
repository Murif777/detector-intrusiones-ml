# data/ — datasets NSL-KDD

No se versiona data cruda. Descarga manual:

1. NSL-KDD (baseline H1):
   - `KDDTrain+.txt` y `KDDTest+.txt` desde https://www.unb.ca/cic/datasets/nsl.html
     (espejo habitual: https://github.com/defcom17/NSL_KDD)
   - Cópialos aquí: `data/KDDTrain+.txt`, `data/KDDTest+.txt`
2. CICIDS2017 subset (H2, después):
   - Solo `Tuesday-WorkingHours.pcap` + CSV de flujos correspondiente
   - Fuente: https://www.unb.ca/cic/datasets/ids-2017.html

Si los archivos no existen, `train_baseline.py --sample` genera datos sintéticos demo
para probar el pipeline sin descargar nada.
