import gzip
import json
import pandas as pd

archivo_entrada = "nvdcve-2.0-2026.json.gz"
archivo_salida = "nist_cve_raw.csv"

print("Leyendo archivo original del NIST...")
with gzip.open(archivo_entrada, "rt", encoding="utf-8") as f:
  data = json.load(f)

filas = []

for item in data.get("vulnerabilities", []):
  cve = item.get("cve", {})

  # 1. Identificador, Fechas y Estado
  cve_id = cve.get("id")
  published = cve.get("published")
  last_modified = cve.get("lastModified")
  vuln_status = cve.get("vulnStatus")
  source_id = cve.get("sourceIdentifier")

  # 2. Texto descriptivo (Inglés)
  descriptions = cve.get("descriptions", [])
  desc_text = next(
      (d.get("value") for d in descriptions if d.get("lang") == "en"), None
  )

  # 3. Numéricas discretas (Conteos)
  references = cve.get("references", [])
  ref_count = len(references) if references else 0

  # 4. Alta cardinalidad (CWE - Tipo de debilidad)
  weaknesses = cve.get("weaknesses", [])
  cwe_id = None
  if weaknesses:
    cwe_desc = weaknesses[0].get("description", [])
    if cwe_desc:
      cwe_id = cwe_desc[0].get("value")

  # 5. Métricas CVSS v3.1 (Continuas, Ordinales, Nominales y Binarias)
  # Si el CVE aún no ha sido analizado, estos campos quedarán como None (NaN en el CSV)
  metrics = cve.get("metrics", {}).get("cvssMetricV31", [])
  if metrics:
    m = metrics[0]
    cvss_data = m.get("cvssData", {})
    base_score = cvss_data.get("baseScore")  # Continua 1
    exploitability_score = m.get("exploitabilityScore")  # Continua 2
    impact_score = m.get("impactScore")  # Continua 3
    base_severity = cvss_data.get(
        "baseSeverity"
    )  # Ordinal (LOW, MEDIUM, HIGH, CRITICAL)
    attack_vector = cvss_data.get(
        "attackVector"
    )  # Nominal (NETWORK, LOCAL, etc.)
    user_interaction = cvss_data.get(
        "userInteraction"
    )  # Binaria (NONE, REQUIRED)
  else:
    base_score = None
    exploitability_score = None
    impact_score = None
    base_severity = None
    attack_vector = None
    user_interaction = None

  filas.append({
      "cve_id": cve_id,
      "published_date": published,
      "last_modified_date": last_modified,
      "vuln_status": vuln_status,
      "source_identifier": source_id,
      "cwe_id": cwe_id,
      "reference_count": ref_count,
      "base_score": base_score,
      "exploitability_score": exploitability_score,
      "impact_score": impact_score,
      "base_severity": base_severity,
      "attack_vector": attack_vector,
      "user_interaction": user_interaction,
      "description": desc_text,
  })

df = pd.DataFrame(filas)
df.to_csv(archivo_salida, index=False, encoding="utf-8")

print(f"\nArchivo generado: {archivo_salida}")
print(f"Total de filas: {len(df)}")
print(f"Total de columnas: {len(df.columns)}")
print("\nPorcentaje de valores faltantes (NaN) por columna:")
print((df.isnull().sum() / len(df) * 100).round(2))