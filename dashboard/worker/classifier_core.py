
# worker/classifier_core.py
import os
import pandas as pd
import numpy as np
import joblib
import subprocess
import sys

# ---------------- Paths ----------------
BASE_DIR = os.path.dirname(__file__)
MODEL_DIR = os.path.join(BASE_DIR, "..", "models")

# ---------------- Column Mapping ----------------
COLUMN_MAPPING = {
    'FlowDuration': 'duration',
    'TotalFwdIAT': 'total_fiat',
    'TotalBwdIAT': 'total_biat',
    'FwdIATMin': 'min_fiat',
    'BwdIATMin': 'min_biat',
    'FwdIATMax': 'max_fiat',
    'BwdIATMax': 'max_biat',
    'FwdIATMean': 'mean_fiat',
    'BwdIATMean': 'mean_biat',
    'PktsPerSec': 'flowPktsPerSecond',
    'BytesPerSec': 'flowBytesPerSecond',
    'FlowIATMin': 'min_flowiat',
    'FlowIATMax': 'max_flowiat',
    'FlowIATMean': 'mean_flowiat',
    'FlowIATStd': 'std_flowiat',
    'MinActive': 'min_active',
    'MeanActive': 'mean_active',
    'MaxActive': 'max_active',
    'StdActive': 'std_active',
    'MinIdle': 'min_idle',
    'MeanIdle': 'mean_idle',
    'MaxIdle': 'max_idle',
    'StdIdle': 'std_idle'
}
MODEL_FEATURES = list(COLUMN_MAPPING.values())

# ---------------- Labels ----------------
LABEL_MAP = {0: "Web", 1: "Multimedia", 2: "Social Media", 3: "Malicious"}

# ---------------- Load Models ----------------
SCALER = joblib.load(os.path.join(MODEL_DIR, "scaler_new_xgb.pkl"))
MODEL = joblib.load(os.path.join(MODEL_DIR, "xgboost_model_new.pkl"))

# ---------------- Helper Functions ----------------
def extract_flows_from_pcap(pcap_path, output_csv="gmflows.csv"):
    """Call the pcap2csv script to convert PCAP → CSV"""
    try:
        subprocess.run(
            [sys.executable, "pcap2csv_win_new.py", "-i", pcap_path, "-o", output_csv],
            check=True,
            cwd=os.path.dirname(__file__)
        )
    except subprocess.CalledProcessError as e:
        print(f"[!] Error running pcap2csv: {e}", file=sys.stderr)
        return None
    return output_csv if os.path.exists(output_csv) else None


def classify_flows(csv_path, last_n_seconds=None):
    import traceback
    import pandas as pd
    import numpy as np
    import os

    df = pd.DataFrame()
    try:
        if not os.path.exists(csv_path):
            print(f"[!] CSV not found: {csv_path}", file=sys.stderr)
            return df

        df_read = pd.read_csv(csv_path)
        if df_read.empty:
            print("[!] CSV is empty", file=sys.stderr)
            return df

        df = df_read.copy()

        # FIX: Only filter if last_n_seconds is provided and valid
        if last_n_seconds is not None and last_n_seconds > 0 and "FlowDuration" in df.columns:
            max_dur = df["FlowDuration"].max()
            threshold = max_dur - last_n_seconds
            original_count = len(df)
            df = df[df["FlowDuration"] >= threshold]
            print(f"[CLASSIFIER] Filtered to last {last_n_seconds}s: {len(df)} rows (from {original_count})", flush=True)
        else:
            print(f"[CLASSIFIER] Using all {len(df)} flows (no time filter)", flush=True)

        # PRESERVE URL DATA BEFORE RENAMING - FIX NaN ISSUE
        url_column = None
        if 'URLs' in df.columns:
            # Convert NaN to empty strings
            url_column = df['URLs'].fillna('')
        elif 'urls' in df.columns:
            url_column = df['urls'].fillna('')

        # Also preserve original IP/port data for frontend
        original_columns = {}
        frontend_columns = ['SrcIP', 'DstIP', 'SrcPort', 'DstPort', 'Protocol']
        for col in frontend_columns:
            if col in df.columns:
                original_columns[col] = df[col]

        # Rename columns safely for model
        df = df.rename(columns={k: v for k, v in COLUMN_MAPPING.items() if k in df.columns})

        # Ensure all model features exist
        for col in MODEL_FEATURES:
            if col not in df.columns:
                df[col] = 0

        df = df[MODEL_FEATURES]
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(0, inplace=True)

        # Prediction
        X_scaled = SCALER.transform(df)
        y_pred = MODEL.predict(X_scaled)
        df["Prediction"] = [LABEL_MAP.get(p, p) for p in y_pred]

        # ADD BACK URL DATA AND ORIGINAL COLUMNS TO FINAL RESULT
        if url_column is not None:
            df["URLs"] = url_column
            
        # Add back original columns for frontend
        for col, data in original_columns.items():
            df[col] = data

        print(f"[CLASSIFIER] Classification complete. Predictions: {df['Prediction'].value_counts().to_dict()}", flush=True)

    except Exception as e:
        print("[!] Exception in classify_flows:", e, file=sys.stderr)
        print(traceback.format_exc(), file=sys.stderr)

    return df

