# Validación del dataset — MCDI500

**Archivo:** `nist_cve_raw.csv` · 85687 filas × 14 columnas

## Perfil de variables

| variable | dtype | rol | unicos | pct_nulos |
| --- | --- | --- | --- | --- |
| cve_id | object | identificador | 85687 | 0.0 |
| published_date | object | fecha | 85687 | 0.0 |
| last_modified_date | object | fecha | 49577 | 0.0 |
| vuln_status | object | nominal | 7 | 0.0 |
| source_identifier | object | alta cardinalidad | 394 | 0.0 |
| cwe_id | object | alta cardinalidad | 594 | 7.6 |
| reference_count | int64 | discreta | 90 | 0.0 |
| base_score | float64 | continua | 82 | 12.4 |
| exploitability_score | float64 | continua | 26 | 12.4 |
| impact_score | float64 | continua | 16 | 12.4 |
| base_severity | object | nominal | 5 | 12.4 |
| attack_vector | object | nominal | 4 | 12.4 |
| user_interaction | object | binaria | 2 | 12.4 |
| description | object | texto libre | 80405 | 0.0 |

## Requisitos del curso

| estado | requisito | detalle |
| --- | --- | --- |
| OK | Al menos 2000 filas | 85687 filas |
| OK | Al menos 12 columnas | 14 columnas |
| OK | Combina al menos 3 roles analíticos | nominal, continua, alta cardinalidad, fecha, discreta, binaria, texto libre |
| OK | Al menos una variable numérica | 4 numéricas (continuas o discretas) |
| OK | Al menos una variable categórica | 4 categóricas (nominales, binarias u ordinales) |
| OK | Presencia de valores faltantes | máximo 12.4% en una variable |
| OK | Ninguna variable sobre 60% de faltantes | máximo 12.4% |
| OK | Incluye alguna variable de fecha | 2 detectadas |
| OK | Incluye texto o categórica de alta cardinalidad | 3 detectadas |
| OK | Archivo bajo 100 MB | 51.6 MB |
| OK | Sin filas duplicadas exactas | ninguna |

## Resultado

El conjunto **cumple** los requisitos mínimos.

## Contraste de Roles Analíticos: Validador vs. Equipo

A continuación, se presenta la comparación entre los roles inferidos automáticamente por el script validador y la clasificación semántica definida por el equipo para las 14 variables del conjunto de datos `nist_cve_raw.csv`:

| # | Variable | Según Validador | Según Equipo | Coincide |
| :--- | :--- | :--- | :--- | :--- |
| 0 | cve_id | identificador | identificador | True |
| 1 | published_date | fecha | fecha | True |
| 2 | last_modified_date | fecha | fecha | True |
| 3 | vuln_status | nominal | nominal | True |
| 4 | source_identifier | alta cardinalidad | alta cardinalidad | True |
| 5 | cwe_id | alta cardinalidad | alta cardinalidad | True |
| 6 | reference_count | discreta | discreta | True |
| 7 | base_score | continua | continua | True |
| 8 | exploitability_score | continua | continua | True |
| 9 | impact_score | continua | continua | True |
| 10 | base_severity | nominal | ordinal | False |
| 11 | attack_vector | nominal | nominal | True |
| 12 | user_interaction | binaria | binaria | True |
| 13 | description | texto libre | texto libre | True |

**Discrepancias:** 1 (`base_severity`)

### Justificación Técnica de la Discrepancia

* **Variable `base_severity` (Validador: `nominal` → Equipo: `ordinal`):**
  * **Causa de la discrepancia automática:** El script validador evalúa las columnas mediante reglas heurísticas generales sin conocer el contexto del negocio. Al inspeccionar `base_severity`, detecta una variable de tipo texto (`object`) con una baja cantidad de valores únicos (5 categorías), asignándole por defecto el rol de categórica `nominal`.
  * **Fundamento del equipo:** En el estándar internacional de ciberseguridad CVSS v3.1 (*Common Vulnerability Scoring System*) del NIST, la severidad base representa una escala jerárquica estricta de criticidad del riesgo: `NONE` < `LOW` < `MEDIUM` < `HIGH` < `CRITICAL`. A diferencia de una variable nominal donde no existe jerarquía entre etiquetas, en `base_severity` existe un orden natural evidente donde una vulnerabilidad `CRITICAL` es más grave que una `HIGH`, y esta a su vez más que una `MEDIUM` o `LOW`.
  * **Impacto en el preprocesamiento:** Si se aceptara la sugerencia del validador (`nominal`) y se aplicara *One-Hot Encoding*, se destruiría la relación de orden y magnitud de riesgo entre las categorías. Por el contrario, al reclasificarla correctamente como **categórica ordinal**, durante la etapa de preprocesamiento se aplicará una codificación ordinal (`OrdinalEncoder` / mapeo explícito) declarando manualmente el orden jerárquico (`['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']` $\rightarrow$ `[0, 1, 2, 3, 4]`). Esto evita que las librerías de Python asignen códigos por orden alfabético (`CRITICAL` = 0, `HIGH` = 1, `LOW` = 2, etc.) y permite cubrir íntegramente los ocho roles analíticos exigidos para el proyecto.