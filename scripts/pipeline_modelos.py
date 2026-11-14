import os
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder, OrdinalEncoder
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.utils.class_weight import compute_class_weight

from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler

import tensorflow as tf
from tensorflow.keras import layers, models, callbacks
import shap

# 1. CARGA Y VERIFICACIÓN DE UNICIDAD (Rol: Identificador)
DATA_PATH = os.path.join("data", "nist_cve_raw.csv")
df = pd.read_csv(DATA_PATH)
print(f"Dataset cargado: {df.shape[0]} filas x {df.shape[1]} columnas")

assert df["cve_id"].nunique() == len(df), "Error: Existen CVE_ID duplicados"
df = df.drop(columns=["cve_id"])  # Excluir identificador del análisis

# 2. TRATAMIENTO DE FECHAS (Rol: Fecha)
df["published_date"] = pd.to_datetime(df["published_date"], errors="coerce", utc=True)
df["last_modified_date"] = pd.to_datetime(df["last_modified_date"], errors="coerce", utc=True)

df["pub_year"] = df["published_date"].dt.year
df["pub_month"] = df["published_date"].dt.month
df["days_to_modify"] = (df["last_modified_date"] - df["published_date"]).dt.days.clip(lower=0)

# 3. DEFINICIÓN DEL PROBLEMA SUPERVISADO
# Filtramos registros que ya cuentan con evaluación de severidad para entrenar supervisadamente,
# conservando las imputaciones sobre cwe_id y puntajes auxiliares si existieran nulos parciales.
df_supervised = df.dropna(subset=["base_severity"]).copy()

# Rol Categórica Ordinal: Declaración explícita del orden jerárquico de base_severity
orden_severidad = [["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]]
ordinal_enc = OrdinalEncoder(categories=orden_severidad, handle_unknown="use_encoded_value", unknown_value=-1)
df_supervised["severity_ordinal"] = ordinal_enc.fit_transform(df_supervised[["base_severity"]])

# Variable objetivo binaria para alerta temprana SOC: Crítica/Alta (1) vs Media/Baja/Ninguna (0)
y = (df_supervised["base_severity"].isin(["HIGH", "CRITICAL"])).astype(int)

# 4. TRATAMIENTO DE LOS ROLES RESTANTES
# Rol Binaria: user_interaction (NONE=0, REQUIRED=1)
df_supervised["user_interaction_bin"] = (df_supervised["user_interaction"] == "REQUIRED").astype(int)

# Rol Alta Cardinalidad: Agrupación por frecuencia (Top 15 + 'Otros')
for col in ["cwe_id", "source_identifier"]:
    df_supervised[col] = df_supervised[col].fillna("Missing")
    top_cats = df_supervised[col].value_counts().nlargest(15).index
    df_supervised[col] = df_supervised[col].where(df_supervised[col].isin(top_cats), "Otros")

# Rol Texto Libre: Extracción de longitud de la descripción técnica
df_supervised["desc_length"] = df_supervised["description"].fillna("").str.len()

# Selección de variables predictoras (evitando fuga de datos directa desde base_score hacia base_severity)
num_cols = ["exploitability_score", "impact_score", "reference_count", "days_to_modify", "desc_length"]
cat_cols = ["vuln_status", "attack_vector", "cwe_id", "source_identifier"]
bin_cols = ["user_interaction_bin"]

X = df_supervised[num_cols + cat_cols + bin_cols].copy()

# 5. PARTICIÓN ESTRATIFICADA: ENTRENAMIENTO (70%), VALIDACIÓN (15%), PRUEBA (15%)
X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.30, stratify=y, random_state=42)
X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.50, stratify=y_temp, random_state=42)

print(f"Train: {X_train.shape}, Val: {X_val.shape}, Test: {X_test.shape}")

# Preprocesamiento numérico (Imputación por mediana + Escalamiento estándar) y categórico (One-Hot Encoding)
num_imputer = SimpleImputer(strategy="median")
scaler = StandardScaler()

X_train_num = scaler.fit_transform(num_imputer.fit_transform(X_train[num_cols]))
X_val_num = scaler.transform(num_imputer.transform(X_val[num_cols]))
X_test_num = scaler.transform(num_imputer.transform(X_test[num_cols]))

ohe = OneHotEncoder(handle_unknown="ignore", sparse_output=False)
X_train_cat = ohe.fit_transform(X_train[cat_cols])
X_val_cat = ohe.transform(X_val[cat_cols])
X_test_cat = ohe.transform(X_test[cat_cols])

feature_names = num_cols + list(ohe.get_feature_names_out(cat_cols)) + bin_cols

X_train_proc = np.hstack([X_train_num, X_train_cat, X_train[bin_cols].values])
X_val_proc = np.hstack([X_val_num, X_val_cat, X_val[bin_cols].values])
X_test_proc = np.hstack([X_test_num, X_test_cat, X_test[bin_cols].values])

# Guardar artefactos para el Backend
os.makedirs("models", exist_ok=True)
joblib.dump({"num_imputer": num_imputer, "scaler": scaler, "ohe": ohe, "features": feature_names}, "models/preprocessor.pkl")

# 6. TRES TÉCNICAS DE BALANCEO DE CLASES
print("\n--- Evaluando Técnicas de Balanceo con Random Forest ---")
escenarios_balanceo = {
    "1_Class_Weight": (X_train_proc, y_train, "balanced"),
    "2_SMOTE": (*SMOTE(random_state=42).fit_resample(X_train_proc, y_train), None),
    "3_UnderSampling": (*RandomUnderSampler(random_state=42).fit_resample(X_train_proc, y_train), None),
}

for nombre, (X_res, y_res, cw) in escenarios_balanceo.items():
    rf_temp = RandomForestClassifier(n_estimators=100, class_weight=cw, random_state=42, n_jobs=-1)
    rf_temp.fit(X_res, y_res)
    preds_val = rf_temp.predict(X_val_proc)
    probs_val = rf_temp.predict_proba(X_val_proc)[:, 1]
    print(f"Escenario {nombre} | ROC-AUC Val: {roc_auc_score(y_val, probs_val):.4f}")

# 7. COMPARACIÓN DE 3 TÉCNICAS DE MACHINE LEARNING CLÁSICO
print("\n--- Entrenando 3 Modelos de Machine Learning ---")
modelos_ml = {
    "Logistic_Regression": LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42),
    "Random_Forest": RandomForestClassifier(n_estimators=150, class_weight="balanced", random_state=42, n_jobs=-1),
    "KNN": KNeighborsClassifier(n_neighbors=7, n_jobs=-1),
}

for nombre, modelo in modelos_ml.items():
    modelo.fit(X_train_proc, y_train)
    probs = modelo.predict_proba(X_val_proc)[:, 1]
    print(f"[ML] {nombre} -> Val ROC-AUC: {roc_auc_score(y_val, probs):.4f}")

# Guardamos Random Forest como modelo productivo ligero para API y SHAP
best_ml = modelos_ml["Random_Forest"]
joblib.dump(best_ml, "models/best_model_rf.pkl")

# 8. COMPARACIÓN DE 3 ARQUITECTURAS DE DEEP LEARNING
print("\n--- Entrenando 3 Arquitecturas de Deep Learning ---")
input_dim = X_train_proc.shape[1]

def build_mlp_base():
    model = models.Sequential([
        layers.Input(shape=(input_dim,)),
        layers.Dense(64, activation="relu"),
        layers.Dense(32, activation="relu"),
        layers.Dense(1, activation="sigmoid")
    ])
    model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["AUC"])
    return model

def build_mlp_deep_bn_dropout():
    model = models.Sequential([
        layers.Input(shape=(input_dim,)),
        layers.Dense(128, activation="relu"),
        layers.BatchNormalization(),
        layers.Dropout(0.3),
        layers.Dense(64, activation="relu"),
        layers.BatchNormalization(),
        layers.Dropout(0.2),
        layers.Dense(32, activation="relu"),
        layers.Dense(1, activation="sigmoid")
    ])
    model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["AUC"])
    return model

def build_conv1d_tabular():
    model = models.Sequential([
        layers.Input(shape=(input_dim, 1)),
        layers.Conv1D(32, kernel_size=3, activation="relu", padding="same"),
        layers.MaxPooling1D(pool_size=2),
        layers.Flatten(),
        layers.Dense(64, activation="relu"),
        layers.Dropout(0.2),
        layers.Dense(1, activation="sigmoid")
    ])
    model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["AUC"])
    return model

early_stop = callbacks.EarlyStopping(monitor="val_AUC", mode="max", patience=3, restore_best_weights=True)

for nombre, builder, reshape in [
    ("DL_1_MLP_Base", build_mlp_base, False),
    ("DL_2_MLP_BN_Dropout", build_mlp_deep_bn_dropout, False),
    ("DL_3_Conv1D_Tabular", build_conv1d_tabular, True)
]:
    X_tr = X_train_proc[..., np.newaxis] if reshape else X_train_proc
    X_v = X_val_proc[..., np.newaxis] if reshape else X_val_proc
    model_dl = builder()
    model_dl.fit(X_tr, y_train, validation_data=(X_v, y_val), epochs=10, batch_size=256, callbacks=[early_stop], verbose=0)
    probs_dl = model_dl.predict(X_v, verbose=0).ravel()
    print(f"[DL] {nombre} -> Val ROC-AUC: {roc_auc_score(y_val, probs_dl):.4f}")

# 9. EVALUACIÓN EN CONJUNTO DE PRUEBA (TEST SET NO VISTO) Y EXPLICABILIDAD SHAP
print("\n--- Evaluación Final en Conjunto de Prueba (Test Set) ---")
test_preds = best_ml.predict(X_test_proc)
test_probs = best_ml.predict_proba(X_test_proc)[:, 1]
print(classification_report(y_test, test_preds, target_names=["Baja/Media (0)", "Alta/Crítica (1)"]))
print(f"Test ROC-AUC Final: {roc_auc_score(y_test, test_probs):.4f}")

# Cálculo de valores SHAP sobre una muestra del conjunto de prueba
explainer = shap.TreeExplainer(best_ml)
sample_idx = np.random.choice(X_test_proc.shape[0], size=min(200, X_test_proc.shape[0]), replace=False)
shap_values = explainer.shap_values(X_test_proc[sample_idx])
print("Análisis SHAP completado exitosamente.")