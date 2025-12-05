from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import numpy as np

# تحميل الموديل والـ scaler
model = joblib.load("rf_cicids_model.joblib")
scaler = joblib.load("scaler.joblib")

app = FastAPI(title="DDoS Detection API")

class FlowData(BaseModel):
    Destination_Port: float
    Flow_Duration: float
    Init_Win_bytes_forward: float
    Init_Win_bytes_backward: float
    Subflow_Fwd_Bytes: float
    Subflow_Bwd_Bytes: float
    act_data_pkt_fwd: float
    min_seg_size_forward: float

@app.post("/predict")
def predict(flow: FlowData):
    X_new = np.array([[
        flow.Destination_Port,
        flow.Flow_Duration,
        flow.Init_Win_bytes_forward,
        flow.Init_Win_bytes_backward,
        flow.Subflow_Fwd_Bytes,
        flow.Subflow_Bwd_Bytes,
        flow.act_data_pkt_fwd,
        flow.min_seg_size_forward
    ]])
    X_new_scaled = scaler.transform(X_new)
    pred = model.predict(X_new_scaled)[0]
    return {"prediction": int(pred), "label": "Benign" if pred == 0 else "Malicious"}
