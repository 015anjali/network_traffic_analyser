from fastapi import FastAPI, Request, HTTPException
import uvicorn
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import UpdateOne
import asyncio
from datetime import datetime, timezone
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
FLUSH_INTERVAL = 5  

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

        # Apply column mapping 
        df = df.rename(columns=config.column_mapping)
        
        # Select only required features 
        df = df[config.model_features]
        
        # Data validation and cleaning
        logger.info(f"Starting classification for {len(flows)} flows")
        
        # Fix extreme IAT values that appear to be timestamps
        iat_columns = ['min_fiat', 'max_fiat', 'min_biat', 'max_biat', 
                      'min_flowiat', 'max_flowiat']
        
        for col in iat_columns:
            if col in df.columns:
                mask = df[col] > 1e12
                if mask.any():
                    logger.warning(f"Found {mask.sum()} flows with extreme {col} values, fixing...")
                    reasonable_values = df[col][~mask]
                    if len(reasonable_values) > 0:
                        replacement = reasonable_values.median()
                    else:
                        replacement = 1000  
                    df.loc[mask, col] = replacement
        
        # Handle infinite and missing values
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(0, inplace=True)
        
        for col in df.columns:
            if df[col].dtype in ['float64', 'int64']:
                if 'duration' in col.lower():
                    df[col] = df[col].clip(upper=1e9)  
                elif 'persecond' in col.lower():
                    df[col] = df[col].clip(upper=1e9)  
                elif col in ['min_fiat', 'max_fiat', 'min_biat', 'max_biat', 
                           'min_flowiat', 'max_flowiat']:
                    df[col] = df[col].clip(upper=1e6)  
        
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
        
        # First check if device already exists by device_id, device_name, or ip_address
        existing_device = await devices_collection.find_one({
            "$or": [
                {"device_id": device_id},
                {"device_name": device_info["device_name"], "ip_address": device_info["ip_address"]}
            ]
        })
        
        if existing_device:
            # Update existing device with new device_id if different
            result = await devices_collection.update_one(
                {"_id": existing_device["_id"]},
                {"$set": {
                    "device_id": device_id,  # Ensure consistent device_id
                    "last_seen": datetime.now(timezone.utc),
                    "status": "active"
                }}
            )
            logger.info(f"Updated existing device {device_id}. Matched: {result.matched_count}, Modified: {result.modified_count}")
        else:
            # Insert new device
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

# Merge duplicate devices endpoint
@app.post("/api/merge-duplicate-devices")
async def merge_duplicate_devices(request: Request):
    """Merge devices with same name and IP but different device_ids"""
    try:
        logger.info("Starting duplicate device merge process")
        
        # Find all devices grouped by name and IP
        pipeline = [
            {
                "$group": {
                    "_id": {"device_name": "$device_name", "ip_address": "$ip_address"},
                    "devices": {"$push": "$$ROOT"},
                    "count": {"$sum": 1}
                }
            },
            {"$match": {"count": {"$gt": 1}}}
        ]
        
        duplicate_groups = await devices_collection.aggregate(pipeline).to_list(None)
        
        merged_count = 0
        for group in duplicate_groups:
            devices = group["devices"]
            # Keep the most recently seen device as the primary
            primary_device = max(devices, key=lambda d: d.get("last_seen", datetime.min))
            other_devices = [d for d in devices if d["_id"] != primary_device["_id"]]
            
            # Merge total flows
            total_flows = sum(d.get("total_flows", 0) for d in devices)
            
            # Update primary device
            await devices_collection.update_one(
                {"_id": primary_device["_id"]},
                {"$set": {"total_flows": total_flows}}
            )
            
            # Delete duplicate devices
            for device in other_devices:
                await devices_collection.delete_one({"_id": device["_id"]})
                # Also update flows to use the primary device_id
                await flows_collection.update_many(
                    {"device_id": device["device_id"]},
                    {"$set": {"device_id": primary_device["device_id"]}}
                )
            
            merged_count += len(other_devices)
            logger.info(f"Merged {len(other_devices)} duplicates for {primary_device['device_name']}")
        
        logger.info(f"Duplicate device merge completed. Merged {merged_count} devices")
        
        return {
            "status": "success",
            "message": f"Merged {merged_count} duplicate devices",
            "merged_count": merged_count
        }
        
    except Exception as e:
        logger.error(f"Error merging duplicate devices: {e}")
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



