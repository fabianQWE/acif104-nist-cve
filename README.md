# Predicción y Priorización de Vulnerabilidades de Ciberseguridad (NIST NVD) — ACIF104

Repositorio oficial de la ** Evaluación Sumativa 1 (Informe Fase 2)** para la asignatura **Aprendizaje de Máquinas (ACIF104)** de la Universidad Andrés Bello.

## Descripción del Proyecto y Dataset
Este proyecto implementa un flujo completo de Ciencia de Datos y Aprendizaje Automático sobre registros reales extraídos de la *National Vulnerability Database (NVD) del presente año* del NIST (`nist_cve_raw.csv`, conformado por **85.687 filas y 14 columnas**, con un peso de **51,6 MB**). 

El conjunto de datos incluye valores faltantes reales en el rango requerido por la cátedra (`7,59%` en `cwe_id` y `12,43%` en las métricas CVSSv3.1 por vulnerabilidades en estado *Awaiting Analysis*) y cubre los **8 roles analíticos** evaluados (Continuas, Discreta, Nominales, Ordinal, Binaria, Fechas, Alta Cardinalidad/Texto Libre e Identificador).

## Estructura del Repositorio
* `data/nist_cve_raw.csv`: Conjunto de datos crudo validado mediante el script de la asignatura (`informe_dataset.md`).
* `scripts/aplanar_nist.py`: Script de extracción directa desde el feed oficial JSON 2.0 del NIST hacia estructura tabular CSV sin alterar valores nulos.
* `scripts/pipeline_modelos.py`: Preprocesamiento por rol analítico, partición estratificada (70/15/15), 3 técnicas de balanceo de clases (Class Weights, SMOTE, Random Under-Sampling), comparación de 3 algoritmos de Machine Learning y 3 arquitecturas de Deep Learning, más explicabilidad mediante **SHAP**.
* `app/backend_api.py` y `app/frontend_ui.py`: Arquitectura desacoplada Backend (FastAPI) y Frontend (Streamlit) con monitoreo de latencia y explicabilidad de inferencias.

## Instrucciones de Instalación y Ejecución

### 1. Clonar el repositorio y crear entorno virtual
```bash
git clone https://github.com/fabianQWE/acif104-nist-cve.git
cd acif104-nist-cve
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
