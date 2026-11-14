import time
import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="NIST CVE Risk Predictor API - ACIF104", version="1.0")

# Carga de modelos y preprocesador
artifacts = joblib.load("models/preprocessor.pkl")
model = joblib.load("models/best_model_rf.pkl")
metrics_log = []

class CVERequest(BaseModel):
    exploitability_score: float = 3.9
    impact_score: float = 5.9
    reference_count: int = 3
    days_to_modify: int = 15
    desc_length: int = 250
    vuln_status: str = "Analyzed"
    attack_vector: str = "NETWORK"
    cwe_id: str = "CWE-79"
    source_identifier: str = "cve@mitre.org"
    user_interaction_bin: int = 0

@app.post("/predict")
def predict_cve(req: CVERequest):
    start_time = time.time()
    df_in = pd.DataFrame([req.model_dump()])
    
    num_cols = ["exploitability_score", "impact_score", "reference_count", "days_to_modify", "desc_length"]
    cat_cols = ["vuln_status", "attack_vector", "cwe_id", "source_identifier"]
    
    X_num = artifacts["scaler"].transform(artifacts["num_imputer"].transform(df_in[num_cols]))
    X_cat = artifacts["ohe"].transform(df_in[cat_cols])
    X_proc = np.hstack([X_num, X_cat, df_in[["user_interaction_bin"]].values])
    
    prob = float(model.predict_proba(X_proc)[0, 1])
    pred = int(prob >= 0.5)
    latency_ms = round((time.time() - start_time) * 1000, 2)
    
    # Importancia local rápida de variables para explicabilidad
    importances = dict(zip(artifacts["features"], model.feature_importances_))
    top_features = sorted(importances.items(), key=lambda x: x[1], reverse=True)[:5]
    
    metrics_log.append({"timestamp": time.time(), "prob": prob, "latency_ms": latency_ms})
    
    return {
        "is_critical_or_high": pred,
        "probability": round(prob, 4),
        "latency_ms": latency_ms,
        "top_explanatory_features": top_features
    }

@app.get("/monitor")
def get_monitoring_metrics():
    if not metrics_log:
        return {"total_requests": 0, "avg_latency_ms": 0.0, "avg_predicted_risk": 0.0}
    return {
        "total_requests": len(metrics_log),
        "avg_latency_ms": round(np.mean([m["latency_ms"] for m in metrics_log]), 2),
        "avg_predicted_risk": round(np.mean([m["prob"] for m in metrics_log]), 4)
    }