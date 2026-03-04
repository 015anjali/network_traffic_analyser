from fastapi import FastAPI, Request, HTTPException
import uvicorn
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import UpdateOne
import asyncio
from datetime import datetime, timedelta, timezone
import os
import joblib
import hashlib 
from dotenv import load_dotenv
from contextlib import asynccontextmanager
import pandas as pd
import numpy as np
import logging
from pathlib import Path

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------- Configuration ----------
BATCH_SIZE = 10
FLUSH_INTERVAL = 5  # seconds

# ---------- Model Configuration ----------
class ModelConfig:
    def __init__(self):
        self.script_dir = Path(__file__).parent
        self.scaler_path = self.script_dir / "models" / "scaler_new_xgb.pkl"
        self.model_path = self.script_dir / "models" / "xgboost_model_new.pkl"
        self.label_map = {0: "Web", 1: "Multimedia", 2: "Social Media", 3: "Malicious"}
        self.column_mapping = {
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
        self.model_features = list(self.column_mapping.values())
        
    def load_models(self):
        """Load scaler and model with error handling"""
        import warnings
        
        # Suppress version warnings for cleaner output
        warnings.filterwarnings('ignore', category=UserWarning, module='sklearn')
        warnings.filterwarnings('ignore', category=FutureWarning)
        
        try:
            logger.info("Loading models...")
            self.scaler = joblib.load(self.scaler_path)
            self.model = joblib.load(self.model_path)
            logger.info(f"Models loaded successfully from {self.script_dir / 'models'}")
            
            # Test model with dummy data to ensure it works
            import numpy as np
            dummy_data = np.zeros((1, len(self.model_features)))
            _ = self.scaler.transform(dummy_data)
            _ = self.model.predict(dummy_data)
            logger.info("Model validation successful")
            
            return True
        except Exception as e:
            logger.error(f"Failed to load models: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return False

# Initialize configuration
config = ModelConfig()
if not config.load_models():
    exit(1)

# ---------- Batch Buffer ----------
flow_buffer = []
buffer_lock = asyncio.Lock()

# ---------- Classification Function ----------
async def classify_and_update(flows):
    """Classify flows and update in database"""
    if not flows:
        return
    
    try:
        df = pd.DataFrame(flows)
        row_ids = df["_id"].tolist()

        # Apply column mapping (same as classify_ui.py)
        df = df.rename(columns=config.column_mapping)
        
        # Select only required features (same as classify_ui.py)
        df = df[config.model_features]
        
        # Data validation and cleaning
        logger.info(f"Starting classification for {len(flows)} flows")
        
        # Fix extreme IAT values that appear to be timestamps
        iat_columns = ['min_fiat', 'max_fiat', 'min_biat', 'max_biat', 
                      'min_flowiat', 'max_flowiat']
        
        for col in iat_columns:
            if col in df.columns:
                # Replace values that are clearly timestamps (> 1e12) with reasonable defaults
                mask = df[col] > 1e12
                if mask.any():
                    logger.warning(f"Found {mask.sum()} flows with extreme {col} values, fixing...")
                    # Use median of reasonable values or default
                    reasonable_values = df[col][~mask]
                    if len(reasonable_values) > 0:
                        replacement = reasonable_values.median()
                    else:
                        replacement = 1000  # Default 1ms
                    df.loc[mask, col] = replacement
        
        # Handle infinite and missing values
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(0, inplace=True)
        
        # Additional validation - check for reasonable ranges
        for col in df.columns:
            if df[col].dtype in ['float64', 'int64']:
                # Cap extreme values to reasonable ranges
                if 'duration' in col.lower():
                    df[col] = df[col].clip(upper=1e9)  # Max ~1000 seconds
                elif 'persecond' in col.lower():
                    df[col] = df[col].clip(upper=1e9)  # Cap packets/bytes per second
                elif col in ['min_fiat', 'max_fiat', 'min_biat', 'max_biat', 
                           'min_flowiat', 'max_flowiat']:
                    df[col] = df[col].clip(upper=1e6)  # Max ~1000 seconds IAT
        
        logger.info(f"Data validation completed. Shape: {df.shape}")

        # Scale and predict
        X_scaled = config.scaler.transform(df)
        y_pred = config.model.predict(X_scaled)
        predicted_classes = [config.label_map.get(p, p) for p in y_pred]

        # Update MongoDB
        update_operations = []
        for row_id, pred in zip(row_ids, predicted_classes):
            update_operations.append(
                UpdateOne(
                    {"_id": row_id}, 
                    {"$set": {"classification": pred, "processed": True}}
                )
            )
            logger.debug(f"Classification for {row_id}: {pred}")
        
        if update_operations:
            result = await flows_collection.bulk_write(update_operations)
            logger.info(f"[SERVER] Classified and updated {len(flows)} flows. Modified: {result.modified_count}")
            
            # Log classification distribution
            class_counts = {}
            for pred in predicted_classes:
                class_counts[pred] = class_counts.get(pred, 0) + 1
            logger.info(f"Classification distribution: {class_counts}")
    
    except Exception as e:
        logger.error(f"Error in classification: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")

# ---------- Periodic Batch Flusher ----------
async def periodic_flush():
    """Periodically flush buffered flows for classification"""
    while True:
        await asyncio.sleep(FLUSH_INTERVAL)
        async with buffer_lock:
            if flow_buffer:
                batch = flow_buffer.copy()
                flow_buffer.clear()
                await classify_and_update(batch)

#---------- MongoDB Atlas Async Setup ----------
MONGO_URI = os.getenv("MONGO_URI")  

if not MONGO_URI:
    logger.error("MONGO_URI not found in environment variables!")
    logger.error("Create a .env file with: MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/")
    exit(1)

logger.info(f"Connecting to MongoDB: {MONGO_URI[:50]}...")

# Global variables for collections
client = None
flows_collection = None
devices_collection = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global client, flows_collection, devices_collection
    
    # Initialize MongoDB connection within the event loop
    try:
        client = AsyncIOMotorClient(MONGO_URI, serverSelectionTimeoutMS=10000)
        # Test connection
        client.admin.command('ping')
        logger.info("MongoDB connection established")
        
        db = client.flowdb
        flows_collection = db.flows
        devices_collection = db.devices
        
        # Start periodic flush in background
        asyncio.create_task(periodic_flush())
        
    except Exception as e:
        logger.error(f"MongoDB connection failed: {e}")
        exit(1)
    
    yield
    
    # Cleanup
    if client:
        client.close()
        logger.info("MongoDB connection closed")

app = FastAPI(title="Network Flow Server", lifespan=lifespan)

# Health check endpoint
@app.get("/")
async def root():
    return {
        "status": "online",
        "service": "Network Flow Server",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

# Register device endpoint
@app.post("/api/register-device")
async def register_device(request: Request):
    try:
        logger.info("Received device registration request")
        data = await request.json()
        logger.debug(f"Registration data: {data}")
        
        device_id = data.get("device_id")
        
        if not device_id:
            logger.error("device_id is required but not provided")
            raise HTTPException(status_code=400, detail="device_id is required")
        
        device_info = {
            "device_id": device_id,
            "device_name": data.get("device_name", "Unknown"),
            "ip_address": data.get("ip_address", "Unknown"),
            "location": data.get("location", "Unknown"),
            "status": "active",
            "registered_at": datetime.now(timezone.utc),
            "last_seen": datetime.now(timezone.utc),
            "total_flows": 0
        }
        
        logger.info(f"Registering device: {device_id}")
        
        # Update or insert device
        result = await devices_collection.update_one(
            {"device_id": device_id},
            {"$set": device_info},
            upsert=True
        )
        
        logger.info(f"Device {device_id} registered successfully. Matched: {result.matched_count}, Modified: {result.modified_count}, Upserted: {result.upserted_id}")
        
        return {
            "status": "success",
            "message": f"Device {device_id} registered",
            "device_id": device_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in device registration: {e}")
        logger.error(f"Exception type: {type(e).__name__}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

# Batch flows endpoint
@app.post("/api/batch-flows")
async def receive_batch_flows(request: Request):
    try:
        logger.info("Received batch flows request")
        data = await request.json()
        logger.debug(f"Batch flows data keys: {list(data.keys())}")
        
        device_id = data.get("device_id")
        flows = data.get("flows", [])
        
        if not device_id:
            logger.error("device_id is required but not provided")
            raise HTTPException(status_code=400, detail="device_id is required")
        
        if not flows:
            logger.warning("No flows provided in batch request")
            raise HTTPException(status_code=400, detail="No flows provided")
        
        logger.info(f"Processing {len(flows)} flows for device {device_id}")
        
        # Process each flow
        flow_documents = []
        received_at = datetime.now(timezone.utc)
        
        for i, flow in enumerate(flows):
            try:
                # Generate unique flow ID
                flow_hash = hashlib.md5(
                    f"{device_id}_{flow.get('flow_id', '')}_{received_at.timestamp()}_{i}".encode()
                ).hexdigest()[:12]
                
                flow_doc = {
                    "_id": f"{device_id}_{flow_hash}",
                    "device_id": device_id,
                    "received_at": received_at,
                    "server_timestamp": datetime.now(timezone.utc).isoformat(),
                    "processed": False,
                    "classification": None,
                    **{k: v for k, v in flow.items() if k not in ['device_id', 'flow_id']}
                }
                
                # Add flow_id if present
                if 'flow_id' in flow:
                    flow_doc['flow_id'] = flow['flow_id']
                
                flow_documents.append(flow_doc)
                
            except Exception as e:
                logger.error(f"Error processing flow {i}: {e}")
                continue
        
        if not flow_documents:
            logger.error("No valid flow documents created")
            raise HTTPException(status_code=400, detail="No valid flows to process")
        
        # Insert into MongoDB
        try:
            result = await flows_collection.insert_many(flow_documents)
            inserted_count = len(result.inserted_ids)
            logger.info(f"Successfully inserted {inserted_count} flows into database")
        except Exception as e:
            logger.error(f"Database insertion error: {e}")
            raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

        # Add to buffer for classification
        async with buffer_lock:
            flow_buffer.extend(flow_documents)
            logger.debug(f"Added {len(flow_documents)} flows to buffer. Buffer size: {len(flow_buffer)}")
            if len(flow_buffer) >= BATCH_SIZE:
                batch = flow_buffer.copy()
                flow_buffer.clear()
                logger.debug(f"Triggering classification for batch of {len(batch)} flows")
                asyncio.create_task(classify_and_update(batch))

        # Update device stats
        try:
            await devices_collection.update_one(
                {"device_id": device_id},
                {
                    "$set": {"last_seen": datetime.now(timezone.utc)},
                    "$inc": {"total_flows": inserted_count}
                }
            )
            logger.info(f"Updated device {device_id} stats with {inserted_count} new flows")
        except Exception as e:
            logger.error(f"Error updating device stats: {e}")

        return {
            "status": "success",
            "message": f"Received {inserted_count} flows",
            "device_id": device_id,
            "batch_size": len(flows),
            "inserted": inserted_count,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in batch flows processing: {e}")
        logger.error(f"Exception type: {type(e).__name__}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

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
    five_min_ago = datetime.now(timezone.utc) - timedelta(minutes=5)
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
        "server_time": datetime.now(timezone.utc).isoformat()
    }

if __name__ == "__main__":
    logger.info("Starting Flow Server...")
    logger.info(f"MongoDB: {MONGO_URI}")
    logger.info(f"Database: flowdb")
    logger.info(f"Collections: devices, flows")
    logger.info(f"API: http://localhost:5000")
    logger.info(f"Model loaded: {config.model_path}")
    logger.info(f"Scaler loaded: {config.scaler_path}")

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=5000,
        log_level="info"
    )



