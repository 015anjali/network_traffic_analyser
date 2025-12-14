from fastapi import FastAPI, Request, HTTPException
import uvicorn
from motor.motor_asyncio import AsyncIOMotorClient
import asyncio
from datetime import datetime
import os
import json
from typing import List, Dict
import uuid
import joblib
import hashlib
from dotenv import load_dotenv
from contextlib import asynccontextmanager
import pandas as pd
import numpy as np

# Load environment variables from .env file
load_dotenv()

# ---------- Load XGBoost Model and Scaler ----------
script_dir = os.path.dirname(__file__)
scaler_path = os.path.join(script_dir, "..", "python files", "models", "scaler_new_xgb.pkl")
model_path = os.path.join(script_dir, "..", "python files", "models", "xgboost_model_new.pkl")

scaler = joblib.load(scaler_path)
model = joblib.load(model_path)
label_map = {0: "Web", 1: "Multimedia", 2: "Social Media", 3: "Malicious"}

column_mapping = {
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
model_features = list(column_mapping.values())

# ---------- Batch Buffer ----------
BATCH_SIZE = 10
flow_buffer = []
buffer_lock = asyncio.Lock()  # ensures thread-safe access

# ---------- Classification Function ----------
async def classify_and_update(flows):
    if not flows:
        return
    df = pd.DataFrame(flows)
    row_ids = df["_id"].tolist()

    # Rename columns and select model features
    df = df.rename(columns=column_mapping)
    df = df.reindex(columns=model_features, fill_value=0)  # handle missing features
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)

    # Scale and predict
    X_scaled = scaler.transform(df)
    y_pred = model.predict(X_scaled)
    predicted_classes = [label_map.get(p, p) for p in y_pred]

    # Update MongoDB
    for row_id, pred in zip(row_ids, predicted_classes):
        await flows_collection.update_one({"_id": row_id}, {"$set": {"classification": pred, "processed": True}})
    
    print(f"[SERVER] Classified and updated {len(flows)} flows.")

# ---------- Periodic Batch Flusher ----------
async def periodic_flush():
    while True:
        await asyncio.sleep(5)  # every 5 seconds
        async with buffer_lock:
            if flow_buffer:
                batch = flow_buffer.copy()
                flow_buffer.clear()
                await classify_and_update(batch)

@asynccontextmanager
async def lifespan(app: FastAPI):
    asyncio.create_task(periodic_flush())  # start periodic flush in background
    yield

app = FastAPI(title="Network Flow Server", lifespan=lifespan)


#---------- MongoDB Atlas Async Setup ----------
MONGO_URI = os.getenv("MONGO_URI")  

if not MONGO_URI:
    print("ERROR: MONGO_URI not found in environment variables!")
    print("Create a .env file with: MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/")
    exit(1)

print(f"Connecting to MongoDB: {MONGO_URI[:50]}...")

try:
    client = AsyncIOMotorClient(MONGO_URI, serverSelectionTimeoutMS=10000)
    print("MongoDB connection established")
except Exception as e:
    print(f"MongoDB connection failed: {e}")
    exit(1)

db = client.flowdb
#collection = db.flows
script_dir = os.path.dirname(__file__)
flows_collection = db.flows
devices_collection = db.devices

# ---------- Load XGBoost Model and Scaler ----------
scaler_path = os.path.join(script_dir, "..", "python files", "models", "scaler_new_xgb.pkl")
model_path = os.path.join(script_dir, "..", "python files", "models", "xgboost_model_new.pkl")

scaler = joblib.load(scaler_path)
model = joblib.load(model_path)
label_map = {0: "Web", 1: "Multimedia", 2: "Social Media", 3: "Malicious"}

column_mapping = {
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
model_features = list(column_mapping.values())

# ---------- Batch Buffer ----------
BATCH_SIZE = 10
flow_buffer = []
buffer_lock = asyncio.Lock()  # ensures thread-safe access



# Health check endpoint
@app.get("/")
async def root():
    return {
        "status": "online",
        "service": "Network Flow Server",
        "timestamp": datetime.utcnow().isoformat()
    }

# Register device endpoint
@app.post("/api/register-device")
async def register_device(request: Request):
    try:
        data = await request.json()
        device_id = data.get("device_id")
        
        if not device_id:
            raise HTTPException(status_code=400, detail="device_id is required")
        
        device_info = {
            "device_id": device_id,
            "device_name": data.get("device_name", "Unknown"),
            "ip_address": data.get("ip_address", "Unknown"),
            "location": data.get("location", "Unknown"),
            "status": "active",
            "registered_at": datetime.utcnow(),
            "last_seen": datetime.utcnow(),
            "total_flows": 0
        }
        
        # Update or insert device
        await devices_collection.update_one(
            {"device_id": device_id},
            {"$set": device_info},
            upsert=True
        )
        
        return {
            "status": "success",
            "message": f"Device {device_id} registered",
            "device_id": device_id
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Batch flows endpoint
@app.post("/api/batch-flows")
async def receive_batch_flows(request: Request):
    try:
        data = await request.json()
        device_id = data.get("device_id")
        flows = data.get("flows", [])
        
        if not device_id:
            raise HTTPException(status_code=400, detail="device_id is required")
        
        if not flows:
            raise HTTPException(status_code=400, detail="No flows provided")
        
        # Process each flow
        flow_documents = []
        received_at = datetime.utcnow()
        
        for flow in flows:
            # Generate unique flow ID
            flow_hash = hashlib.md5(
                f"{device_id}_{flow.get('flow_id', '')}_{received_at.timestamp()}".encode()
            ).hexdigest()[:12]
            
            flow_doc = {
                "_id": f"{device_id}_{flow_hash}",
                "device_id": device_id,
                "received_at": received_at,
                "server_timestamp": datetime.utcnow().isoformat(),
                "processed": False,
                "classification": None,
                **{k: v for k, v in flow.items() if k not in ['device_id', 'flow_id']}
            }
            
            # Add flow_id if present
            if 'flow_id' in flow:
                flow_doc['flow_id'] = flow['flow_id']
            
            flow_documents.append(flow_doc)
        
        # Insert into MongoDB
        if flow_documents:
            result = await flows_collection.insert_many(flow_documents)
            inserted_count = len(result.inserted_ids)
        else:
            inserted_count = 0

        # Add to buffer for classification
        async with buffer_lock:
            flow_buffer.extend(flow_documents)
            print(f"[DEBUG] Added {len(flow_documents)} flows to buffer. Buffer size: {len(flow_buffer)}")
            if len(flow_buffer) >= BATCH_SIZE:
                batch = flow_buffer.copy()
                flow_buffer.clear()
                print(f"[DEBUG] Triggering classification for batch of {len(batch)} flows")
                asyncio.create_task(classify_and_update(batch))

        # Update device stats
        await devices_collection.update_one(
            {"device_id": device_id},
            {
                "$set": {"last_seen": datetime.utcnow()},
                "$inc": {"total_flows": inserted_count}
            }
        )

        return {
            "status": "success",
            "message": f"Received {inserted_count} flows",
            "device_id": device_id,
            "batch_size": len(flows),
            "inserted": inserted_count,
            "timestamp": received_at.isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Get device info
@app.get("/api/devices/{device_id}")
async def get_device_info(device_id: str):
    device = await devices_collection.find_one(
        {"device_id": device_id},
        {"_id": 0}
    )
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    # Count flows for this device
    flow_count = await flows_collection.count_documents({"device_id": device_id})
    device["flow_count"] = flow_count
    
    return device

# Get recent flows
@app.get("/api/flows/recent")
async def get_recent_flows(limit: int = 100, device_id: str = None):
    query = {}
    if device_id:
        query["device_id"] = device_id
    
    cursor = flows_collection.find(
        query,
        {"_id": 0, "device_id": 1, "received_at": 1, "SrcIP": 1, "DstIP": 1, "Protocol": 1}
    ).sort("received_at", -1).limit(limit)
    
    flows = await cursor.to_list(length=limit)
    
    return {
        "count": len(flows),
        "flows": flows
    }

# Stats endpoint
@app.get("/api/stats")
async def get_stats():
    # Count total devices
    device_count = await devices_collection.count_documents({})
    
    # Count total flows
    flow_count = await flows_collection.count_documents({})
    
    # Get active devices (seen in last 5 minutes)
    five_min_ago = datetime.utcnow() - asyncio.timedelta(minutes=5)
    active_devices = await devices_collection.count_documents({
        "last_seen": {"$gte": five_min_ago}
    })
    
    return {
        "devices": {
            "total": device_count,
            "active": active_devices
        },
        "flows": {
            "total": flow_count
        },
        "server_time": datetime.utcnow().isoformat()
    }

if __name__ == "__main__":
    print("Starting Flow Server...")
    print(f"MongoDB: {MONGO_URI}")
    print(f"Database: flowdb")
    print(f"Collections: devices, flows")
    print(f"API: http://localhost:5000")
    print(f"Model loaded: {model_path}")
    print(f"Scaler loaded: {scaler_path}")

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=5000,
        log_level="info"
    )
