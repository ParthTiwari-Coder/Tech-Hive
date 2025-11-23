"""
FastAPI Backend for Intrusion Detection System
Integrates React frontend with Python ML scripts (nn.py, b_kfinal.py, shap_explaienr.py)
"""
import os
import sys
import json
import joblib
import subprocess
import re
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
import asyncio

import pandas as pd
import numpy as np
from fastapi import FastAPI, File, UploadFile, HTTPException, Query, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel


ARTIFACTS_DIR = Path("artifacts")
UPLOADS_DIR = Path("uploads")
MODEL_PATH = "xgboost_zero_fn.pkl"

# Create directories if they don't exist
ARTIFACTS_DIR.mkdir(exist_ok=True)
UPLOADS_DIR.mkdir(exist_ok=True)


app = FastAPI(
    title="IDS ML Backend API",
    description="Backend API for Intrusion Detection System with ML/Blockchain",
    version="1.0.0"
)

# CORS Configuration - Allow React dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files (artifacts like PNGs, JSONs, CSVs)
app.mount("/static", StaticFiles(directory=str(ARTIFACTS_DIR)), name="static")



def get_latest_file(pattern: str, directory: Path = Path(".")) -> Optional[Path]:
    """Get the most recent file matching pattern"""
    files = list(directory.glob(pattern))
    if not files:
        return None
    return max(files, key=lambda p: p.stat().st_mtime)

def copy_to_artifacts(file_path: Path) -> str:
    """Copy file to artifacts directory and return static URL"""
    if not file_path.exists():
        return None
    
    dest = ARTIFACTS_DIR / file_path.name
    
    # Copy file
    import shutil
    shutil.copy2(file_path, dest)
    
    return f"/static/{file_path.name}"

def ensure_artifacts_have_outputs():
    """Ensure generated outputs are in artifacts directory"""
    # List of files that nn.py generates
    model_outputs = [
        "xgboost_zero_fn_confusion_matrix.png",
        "xgboost_zero_fn_feature_importance.png",
        "xgboost_zero_fn_roc_curve.png",
        "xgboost_zero_fn_threshold_analysis.png",
        "xgboost_zero_fn_metrics_vs_threshold.png",
    ]
    
    for filename in model_outputs:
        src = Path(filename)
        if src.exists():
            copy_to_artifacts(src)


@app.get("/")
def read_root():
    """Health check endpoint"""
    return {
        "status": "online",
        "message": "IDS ML Backend API",
        "version": "1.0.0",
        "endpoints": {
            "dashboard": "/api/dashboard",
            "detect": "/api/detect (POST)",
            "threat_log": "/api/threat-log/latest",
            "analytics": "/api/analytics/shap (POST)"
        }
    }

@app.get("/api/dashboard")
def get_dashboard_metrics():
    """
    Get dashboard metrics from trained model
    Returns: confusion matrix image, feature importance image, and performance metrics
    """
    try:
        # Ensure artifacts exist
        ensure_artifacts_have_outputs()
        
        # Load model to get metrics
        if not Path(MODEL_PATH).exists():
            raise HTTPException(
                status_code=404,
                detail=f"Model file '{MODEL_PATH}' not found. Please run nn.py first to train the model."
            )
        
        model_package = joblib.load(MODEL_PATH)
        performance = model_package.get("performance", {})
        
        # Debug: Print what we got from the model
        print(f"\n[DEBUG] Performance data from model: {performance}")
        
        # Ensure values are floats, not numpy types
        accuracy = float(performance.get("accuracy", 0.0))
        precision = float(performance.get("precision", 0.0))
        recall = float(performance.get("recall", 1.0))
        f1 = float(performance.get("f1_score", 0.0))
        roc_auc = float(performance.get("roc_auc", 0.0))
        threshold = float(performance.get("threshold", 0.12))
        
        print(f"[DEBUG] Parsed metrics:")
        print(f"  Accuracy: {accuracy}")
        print(f"  Precision: {precision}")
        print(f"  Recall: {recall}")
        print(f"  F1: {f1}")
        print(f"  ROC-AUC: {roc_auc}")
        print(f"  Threshold: {threshold}")
        
        # Build response
        response = {
            "metrics": {
                "accuracy": accuracy,
                "precision": precision,
                "recall": recall,
                "f1": f1,
                "roc_auc": roc_auc,
                "threshold": threshold,
                "false_negatives": int(performance.get("false_negatives", 0)),
                "false_positives": int(performance.get("false_positives", 0)),
            },
            "images": {
                "confusion_matrix": "/static/xgboost_zero_fn_confusion_matrix.png",
                "feature_importance": "/static/xgboost_zero_fn_feature_importance.png",
                "roc_curve": "/static/xgboost_zero_fn_roc_curve.png",
                "threshold_analysis": "/static/xgboost_zero_fn_threshold_analysis.png",
            },
            "model_info": {
                "threshold": threshold,
                "status": "online"
            }
        }
        
        print(f"[DEBUG] Response being sent: {response}")
        
        return response
        
    except Exception as e:
        print(f"[ERROR] Dashboard error: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error loading dashboard data: {str(e)}")

@app.post("/api/detect")
async def run_detection(file: UploadFile):
    """
    Run intrusion detection on uploaded CSV
    Uses b_kfinal.py to process the file
    """
    try:
        # Validate file type
        if not file.filename.endswith('.csv'):
            raise HTTPException(status_code=400, detail="Only CSV files are accepted")
        
        # Save uploaded file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        upload_path = UPLOADS_DIR / f"detect_{timestamp}.csv"
        
        # Read file content
        content = await file.read()
        with open(upload_path, "wb") as f:
            f.write(content)
        
        print(f"✅ Saved upload to: {upload_path}")
        
        # Run b_kfinal.py via subprocess
        # Feed CSV path via stdin
        print(f"🚀 Running b_kfinal.py on {upload_path}...")
        
        # Set environment to use UTF-8 encoding for subprocess
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        
        process = subprocess.Popen(
            [sys.executable, "b_kfinal.py"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='replace',  # Replace encoding errors instead of failing
            env=env
        )
        
        # Send CSV path to stdin
        stdout, stderr = process.communicate(input=f"{upload_path}\n", timeout=300)
        
        if process.returncode != 0:
            print(f"❌ b_kfinal.py error: {stderr}")
            raise HTTPException(status_code=500, detail=f"Detection script failed: {stderr}")
        
        print("✅ b_kfinal.py completed successfully")
        
        # Find generated files
        predictions_csv = get_latest_file("predictions_with_actions_*.csv")
        blockchain_json = get_latest_file("blockchain_threat_log_*.json")
        
        if not predictions_csv:
            raise HTTPException(status_code=500, detail="Predictions CSV not generated")
        
        # Parse predictions CSV
        df_results = pd.read_csv(predictions_csv)
        
        # Calculate summary
        total_samples = len(df_results)
        intrusions = df_results[df_results['predicted_class'] == 'intrusion']
        normals = df_results[df_results['predicted_class'] == 'normal']
        
        intrusion_count = len(intrusions)
        normal_count = len(normals)
        
        # Build intrusion details list with proper severity and actions
        intrusion_list = []
        for idx, row in intrusions.iterrows():
            # Get severity info
            severity_level = int(row.get('severity_level', 1))
            severity_name = str(row.get('severity_name', 'LOW RISK'))
            probability = float(row.get('intrusion_probability', 0))
            
            # Get action summary from CSV
            action_summary = str(row.get('action_summary', ''))
            
            # Try to parse immediate actions if available
            immediate_actions = []
            monitoring_actions = []
            
            # Generate default actions based on severity if not in CSV
            if severity_level == 3:
                immediate_actions = [
                    'BLOCK this source IP immediately',
                    'Add IP to firewall blacklist',
                    'Drop all packets from this source',
                    'Cut off active connections'
                ]
                monitoring_actions = [
                    'Check if other IPs from same network are attacking',
                    'Look for signs of system compromise',
                    'Check if IP is part of known botnet'
                ]
                explanation = f'This is a serious attack in progress ({probability:.1%} confident). Block immediately!'
            elif severity_level == 2:
                immediate_actions = [
                    'Mark this traffic for immediate security review',
                    'Slow down or limit data from this source',
                    'Activate intrusion detection systems'
                ]
                monitoring_actions = [
                    'Monitor this source IP in real-time',
                    'Check security logs for previous activity',
                    'Look up IP reputation online'
                ]
                explanation = f'This is likely a real intrusion attempt ({probability:.1%} confident). Requires prompt attention.'
            else:
                immediate_actions = [
                    'Allow the traffic but keep a close watch on it',
                    'Turn on detailed packet inspection'
                ]
                monitoring_actions = [
                    'Watch connection frequency over next 5 minutes',
                    'Look for unusual patterns',
                    'Track data volume'
                ]
                explanation = f'This traffic looks somewhat suspicious ({probability:.1%} confident it might be an intrusion).'
            
            # Extract network features if available
            network_features = {}
            feature_cols = ['src_bytes', 'dst_bytes', 'count', 'srv_count', 'serror_rate', 'duration']
            for col in feature_cols:
                if col in row.index:
                    network_features[col] = float(row[col]) if pd.notna(row[col]) else 0
            
            intrusion_list.append({
                "sample_index": int(idx),
                "intrusion_probability": probability,
                "severity_name": severity_name,
                "severity_level": severity_level,
                "explanation": explanation,
                "action": action_summary,
                "immediate_actions": immediate_actions,
                "monitoring_actions": monitoring_actions,
                "network_features": network_features
            })
        
        # Copy blockchain JSON to artifacts
        blockchain_url = None
        if blockchain_json:
            blockchain_url = copy_to_artifacts(blockchain_json)
        
        # Copy predictions CSV to artifacts
        predictions_url = copy_to_artifacts(predictions_csv)
        
        response = {
            "summary": {
                "total_samples": total_samples,
                "intrusions": intrusion_count,
                "normals": normal_count,
            },
            "intrusions": intrusion_list[:100],  # Limit to 100 for performance
            "blockchain_file": blockchain_url,
            "predictions_file": predictions_url,
            "timestamp": timestamp
        }
        
        return response
        
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Detection script timed out (>5 minutes)")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Detection error: {str(e)}")

@app.get("/api/threat-log/latest")
def get_threat_log(download: bool = Query(False)):
    """
    Get latest blockchain threat log
    If download=true, returns file for download
    """
    try:
        # Find latest blockchain JSON
        blockchain_json = get_latest_file("blockchain_threat_log_*.json")
        
        if not blockchain_json:
            # Check artifacts directory
            blockchain_json = get_latest_file("blockchain_threat_log_*.json", ARTIFACTS_DIR)
        
        if not blockchain_json:
            return {
                "file": None,
                "info": {},
                "blocks": [],
                "message": "No blockchain logs found yet. Upload a CSV for detection first."
            }
        
        # Copy to artifacts if not already there
        static_url = copy_to_artifacts(blockchain_json)
        
        # If download requested, return file
        if download:
            return FileResponse(
                path=blockchain_json,
                filename=blockchain_json.name,
                media_type="application/json"
            )
        
        # Parse and return blockchain data
        with open(blockchain_json, 'r') as f:
            blockchain_data = json.load(f)
        
        info = blockchain_data.get("blockchain_info", {})
        blocks = blockchain_data.get("blocks", [])
        
        # Transform blocks for frontend (skip genesis block)
        transformed_blocks = []
        for block in blocks:
            if block.get("index", 0) == 0:
                continue  # Skip genesis block
            
            data = block.get("data", {})
            network_features = data.get("network_features", {})
            
            transformed_blocks.append({
                "id": block.get("index"),
                "timestamp": block.get("timestamp"),
                "sourceIp": network_features.get("src_ip", "N/A"),
                "destIp": network_features.get("dst_ip", "N/A"),
                "protocol": network_features.get("protocol_type", "N/A"),
                "type": data.get("severity_name", "Unknown"),
                "confidence": data.get("intrusion_probability", 0),
                "action": data.get("action_summary", ""),
                "status": "logged",
                "hash": block.get("hash", ""),
                "previous_hash": block.get("previous_hash", ""),
                "sample_index": data.get("sample_index", -1),
                "severity_level": data.get("severity_level", 0),
                "immediate_actions": data.get("immediate_actions", []),
            })
        
        return {
            "file": static_url,
            "info": info,
            "blocks": transformed_blocks,
            "total_blocks": len(transformed_blocks)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error loading threat log: {str(e)}")

@app.post("/api/analytics/shap")
async def run_shap_analysis(file: UploadFile):
    """
    Run SHAP/XAI analysis on uploaded CSV
    Uses shap_explaienr.py to generate explanations
    """
    try:
        # Validate file
        if not file.filename.endswith('.csv'):
            raise HTTPException(status_code=400, detail="Only CSV files are accepted")
        
        # Save uploaded file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        upload_path = UPLOADS_DIR / f"shap_{timestamp}.csv"
        
        # Read file content
        content = await file.read()
        with open(upload_path, "wb") as f:
            f.write(content)
        
        print(f"✅ Saved upload to: {upload_path}")
        
        # Run shap_explaienr.py via subprocess
        # Automatically select options: 7 (generate all), 8 (export), 10 (exit)
        print(f"🚀 Running shap_explaienr.py on {upload_path}...")
        
        # Prepare input commands
        commands = f"{upload_path}\n7\n8\n10\n"
        
        # Set environment to use UTF-8 encoding for subprocess
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        
        process = subprocess.Popen(
            [sys.executable, "shap_explaienr.py"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='replace',  # Replace encoding errors instead of failing
            env=env
        )
        
        stdout, stderr = process.communicate(input=commands, timeout=600)  # 10 min timeout
        
        if process.returncode != 0:
            print(f"⚠️ shap_explaienr.py stderr: {stderr}")
            # Note: script might exit with error code even on success, check for outputs
        
        print("✅ shap_explaienr.py completed")
        
        # Extract intrusion/normal counts from stdout
        intrusion_count = 0
        normal_count = 0
        
        # Parse stdout for counts
        intrusion_match = re.search(r'Intrusions detected:\s*(\d+)', stdout)
        normal_match = re.search(r'Normal traffic:\s*(\d+)', stdout)
        
        if intrusion_match:
            intrusion_count = int(intrusion_match.group(1))
        if normal_match:
            normal_count = int(normal_match.group(1))
        
        # Find generated files
        shap_files = {
            "global_importance": "global_feature_importance_comparison.png",
            "shap_beeswarm": "shap_beeswarm_plot.png",
            "shap_bar": "shap_bar_plot.png",
            "category_importance": "category_importance.png",
            "intrusions_summary": "shap_intrusions_summary.png",
            "intrusion_vs_normal": "intrusion_vs_normal_comparison.png",
        }
        
        images = {}
        for key, filename in shap_files.items():
            file_path = Path(filename)
            if file_path.exists():
                images[key] = copy_to_artifacts(file_path)
            else:
                images[key] = None
        
        # Find XAI predictions CSV
        xai_csv = get_latest_file("xai_predictions_*.csv")
        csv_url = copy_to_artifacts(xai_csv) if xai_csv else None
        
        response = {
            "summary": {
                "intrusions": intrusion_count,
                "normals": normal_count,
                "total": intrusion_count + normal_count
            },
            "images": images,
            "csv": {
                "xai_predictions": csv_url
            },
            "log": stdout[-5000:],  # Last 5000 chars of output
            "timestamp": timestamp
        }
        
        return response
        
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="SHAP analysis timed out (>10 minutes)")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SHAP analysis error: {str(e)}")



@app.get("/api/model/status")
def get_model_status():
    """Check if model is trained and ready"""
    model_exists = Path(MODEL_PATH).exists()
    
    if not model_exists:
        return {
            "status": "offline",
            "message": "Model not found. Please run nn.py to train the model.",
            "model_path": MODEL_PATH
        }
    
    try:
        model_package = joblib.load(MODEL_PATH)
        return {
            "status": "online",
            "message": "Model loaded successfully",
            "threshold": model_package.get("zero_fn_threshold", 0.12),
            "features": len(model_package.get("feature_names", [])),
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error loading model: {str(e)}"
        }

@app.get("/api/files/list")
def list_generated_files():
    """List all generated files in artifacts directory"""
    files = {
        "images": [],
        "data": [],
        "blockchain": []
    }
    
    for file_path in ARTIFACTS_DIR.iterdir():
        if file_path.is_file():
            file_info = {
                "name": file_path.name,
                "url": f"/static/{file_path.name}",
                "size": file_path.stat().st_size,
                "modified": datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
            }
            
            if file_path.suffix == '.png':
                files["images"].append(file_info)
            elif file_path.suffix == '.csv':
                files["data"].append(file_info)
            elif file_path.suffix == '.json':
                files["blockchain"].append(file_info)
    
    return files



if __name__ == "__main__":
    import uvicorn
    
    print("=" * 80)
    print("🚀 Starting IDS ML Backend API Server")
    print("=" * 80)
    print(f"\n📂 Artifacts directory: {ARTIFACTS_DIR.absolute()}")
    print(f"📂 Uploads directory: {UPLOADS_DIR.absolute()}")
    print(f"🤖 Model path: {MODEL_PATH}")
    print(f"\n🌐 API will be available at: http://localhost:8000")
    print(f"📚 API docs at: http://localhost:8000/docs")
    print(f"\n⚙️  Make sure to:")
    print(f"   1. Run nn.py first to train model")
    print(f"   2. Have Train_data.csv and Test_data.csv available")
    print(f"   3. Start React frontend with: npm start")
    print("=" * 80)
    
    uvicorn.run(
        "api:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )