import streamlit as st
import requests

st.set_page_config(page_title="SOC CVE Triage - ACIF104", layout="wide")
st.title("🛡️ Sistema de Priorización y Explicabilidad de Vulnerabilidades NIST (CVE)")

col1, col2 = st.columns(2)
with col1:
    st.subheader("Parámetros de la Vulnerabilidad")
    exp_score = st.slider("Exploitability Score (CVSS)", 0.0, 10.0, 3.9, 0.1)
    imp_score = st.slider("Impact Score (CVSS)", 0.0, 10.0, 5.9, 0.1)
    attack_vec = st.selectbox("Vector de Ataque", ["NETWORK", "LOCAL", "ADJACENT_NETWORK", "PHYSICAL"])
    user_int = st.selectbox("Interacción de Usuario Requerida", ["NONE", "REQUIRED"])
    cwe_id = st.text_input("Debilidad Asociada (CWE)", "CWE-79")
    ref_count = st.number_input("Cantidad de Referencias Técnicas", 0, 100, 4)

if st.button("Evaluar Criticidad"):
    payload = {
        "exploitability_score": exp_score,
        "impact_score": imp_score,
        "reference_count": ref_count,
        "days_to_modify": 10,
        "desc_length": 280,
        "vuln_status": "Analyzed",
        "attack_vector": attack_vec,
        "cwe_id": cwe_id,
        "source_identifier": "cve@mitre.org",
        "user_interaction_bin": 1 if user_int == "REQUIRED" else 0
    }
    res = requests.post("http://127.0.0.1:8000/predict", json=payload).json()
    with col2:
        st.subheader("Resultado del Modelo y Explicabilidad")
        estado = "🚨 ALTA / CRÍTICA" if res["is_critical_or_high"] == 1 else "✅ BAJA / MEDIA"
        st.metric("Nivel de Prioridad Estimado", estado, f"Probabilidad: {res['probability']*100:.1f}%")
        st.write(f"**Latencia de inferencia:** {res['latency_ms']} ms")
        st.write("**Top 5 Factores Explicativos del Modelo:**")
        st.json(dict(res["top_explanatory_features"]))