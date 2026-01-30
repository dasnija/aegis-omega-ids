"""
FastAPI Backend for Hybrid IDS Inference Pipeline

This module provides a REST API for:
1. PCAP file upload
2. PCAP to CSV conversion
3. Model inference 
4. JSON result export

Author: AI Generated
Date: 2025
"""

import os
import sys
import json
import uuid
import shutil
import tempfile
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel
import pandas as pd

# Add parent directories to sys.path for imports
BACKEND_DIR = Path(__file__).parent.absolute()
# Use the actual repo directory name `pcap_to_csv` (no spaces)
PCAP_TO_CSV_DIR = BACKEND_DIR.parent / "pcap_to_csv"
sys.path.insert(0, str(BACKEND_DIR))
sys.path.insert(0, str(PCAP_TO_CSV_DIR))

# Configure logging - write to both console and file
LOG_FILE = BACKEND_DIR / "logs" / "server.log"
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

# Create formatters and handlers
log_format = '%(asctime)s - %(levelname)s - [%(name)s] - %(message)s'
file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(logging.Formatter(log_format))

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter(log_format))

# Setup root logger
logging.basicConfig(
    level=logging.DEBUG,
    format=log_format,
    handlers=[file_handler, console_handler]
)
logger = logging.getLogger(__name__)

# Import database module
import database as db

# ============================================================================
# FASTAPI APP SETUP
# ============================================================================

app = FastAPI(
    title="Hybrid IDS Inference API",
    description="API for network traffic analysis using PCAP files and ML-based intrusion detection",
    version="1.0.0"
)

# CORS middleware for frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# DIRECTORIES & CONFIGURATION
# ============================================================================

UPLOAD_DIR = BACKEND_DIR / "uploads"
RESULTS_DIR = BACKEND_DIR / "inference_results"
TEMP_DIR = BACKEND_DIR / "temp_processing"
MODELS_DIR = BACKEND_DIR / "models"

# Create directories
for directory in [UPLOAD_DIR, RESULTS_DIR, TEMP_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Job status persistence file
JOBS_FILE = BACKEND_DIR / "jobs.json"

def load_jobs() -> Dict[str, Dict[str, Any]]:
    """Load jobs from persistent storage"""
    if JOBS_FILE.exists():
        try:
            with open(JOBS_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load jobs file: {e}")
    return {}

def save_jobs():
    """Save jobs to persistent storage"""
    try:
        with open(JOBS_FILE, 'w') as f:
            json.dump(job_statuses, f, indent=2)
    except Exception as e:
        logger.warning(f"Failed to save jobs file: {e}")

# Store job statuses (load from file if exists)
job_statuses: Dict[str, Dict[str, Any]] = load_jobs()

# ============================================================================
# GLOBAL INFERENCE ENGINE (Pre-loaded at startup for fast inference)
# ============================================================================
inference_engine = None  # Will be initialized at startup (see startup_event below InferenceEngine class)

# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class JobStatus(BaseModel):
    job_id: str
    status: str  # 'pending', 'processing', 'converting', 'inferencing', 'completed', 'failed'
    progress: int  # 0-100
    message: str
    created_at: str
    completed_at: Optional[str] = None
    result_file: Optional[str] = None
    error: Optional[str] = None
    stats: Optional[Dict[str, Any]] = None

class InferenceResult(BaseModel):
    job_id: str
    total_flows: int
    malicious_count: int
    benign_count: int
    detection_rate: float
    results: List[Dict[str, Any]]

# ============================================================================
# PCAP TO CSV CONVERTER
# ============================================================================

class PCAPConverter:
    """Handles PCAP to CSV conversion using the pcap to csv pipeline"""
    
    def __init__(self):
        self.flow_extractor = None
        self.payload_extractor = None
        self.merger = None
        self._load_modules()
    
    def _load_modules(self):
        """Load pcap to csv modules"""
        try:
            from flow_extractor import extract_flow_features
            from payload_extractor import extract_payload_features
            from merger import merge_flow_payload
            
            self.flow_extractor = extract_flow_features
            self.payload_extractor = extract_payload_features
            self.merger = merge_flow_payload
            logger.info(" PCAP to CSV modules loaded successfully")
        except ImportError as e:
            logger.error(f"Failed to load PCAP to CSV modules: {e}")
            raise
    
    def convert(self, pcap_path: Path, output_dir: Path, job_id: str) -> Path:
        """
        Convert PCAP file to merged CSV
        
        Args:
            pcap_path: Path to the PCAP file
            output_dir: Directory to save output files
            job_id: Job identifier for tracking
            
        Returns:
            Path to the merged CSV file
        """
        import time
        import traceback
        
        logger.info(f"[{job_id}] ========== PCAP TO CSV CONVERSION START ==========")
        logger.info(f"[{job_id}] PCAP file: {pcap_path}")
        logger.info(f"[{job_id}] PCAP exists: {pcap_path.exists()}")
        logger.info(f"[{job_id}] PCAP size: {pcap_path.stat().st_size if pcap_path.exists() else 'N/A'} bytes")
        logger.info(f"[{job_id}] Output dir: {output_dir}")
        
        # Define output files
        flow_csv = output_dir / f"{job_id}_flow.csv"
        payload_csv = output_dir / f"{job_id}_payloads.csv"
        merged_csv = output_dir / f"{job_id}_merged.csv"
        
        total_start = time.time()
        
        try:
            # Step 1: Extract flow features
            step_start = time.time()
            logger.info(f"[{job_id}] STEP 1/3: Extracting flow features...")
            update_job_status(job_id, "converting", 20, "Step 1/3: Extracting flow features from PCAP...")
            
            try:
                self.flow_extractor(str(pcap_path), str(flow_csv))
                logger.info(f"[{job_id}]  Flow extraction complete in {time.time() - step_start:.2f}s")
                logger.info(f"[{job_id}]   Output: {flow_csv} (exists: {flow_csv.exists()})")
            except Exception as e:
                logger.error(f"[{job_id}]  Flow extraction FAILED: {e}")
                logger.error(f"[{job_id}] Traceback:\n{traceback.format_exc()}")
                raise
            
            # Step 2: Extract payload features
            step_start = time.time()
            logger.info(f"[{job_id}] STEP 2/3: Extracting HTTP payload features...")
            update_job_status(job_id, "converting", 40, "Step 2/3: Extracting HTTP payloads (requires tshark)...")
            
            try:
                self.payload_extractor(str(pcap_path), None, str(payload_csv))
                logger.info(f"[{job_id}]  Payload extraction complete in {time.time() - step_start:.2f}s")
                logger.info(f"[{job_id}]   Output: {payload_csv} (exists: {payload_csv.exists()})")
            except Exception as e:
                logger.error(f"[{job_id}] Payload extraction FAILED: {e}")
                logger.error(f"[{job_id}] Traceback:\n{traceback.format_exc()}")
                raise
            
            # Step 3: Merge features
            step_start = time.time()
            logger.info(f"[{job_id}] STEP 3/3: Merging flow and payload features...")
            update_job_status(job_id, "converting", 60, "Step 3/3: Merging flow and payload features...")
            
            try:
                self.merger(str(flow_csv), str(payload_csv), str(merged_csv))
                logger.info(f"[{job_id}]  Merge complete in {time.time() - step_start:.2f}s")
                logger.info(f"[{job_id}]   Output: {merged_csv} (exists: {merged_csv.exists()})")
            except Exception as e:
                logger.error(f"[{job_id}]  Merge FAILED: {e}")
                logger.error(f"[{job_id}] Traceback:\n{traceback.format_exc()}")
                raise
            
            logger.info(f"[{job_id}] ========== PCAP CONVERSION COMPLETE ==========")
            logger.info(f"[{job_id}] Total conversion time: {time.time() - total_start:.2f}s")
            return merged_csv
            
        except Exception as e:
            logger.error(f"[{job_id}] ========== PCAP CONVERSION FAILED ==========")
            logger.error(f"[{job_id}] Error: {e}")
            logger.error(f"[{job_id}] Full traceback:\n{traceback.format_exc()}")
            raise

# ============================================================================
# INFERENCE ENGINE
# ============================================================================

class InferenceEngine:
    """Handles ML model inference using the enhanced inference pipeline"""
    
    def __init__(self):
        self.pipeline = None
        self._initialized = False
    
    def initialize(self):
        """Initialize the inference pipeline (lazy loading)"""
        if self._initialized:
            return
            
        logger.info("Initializing inference pipeline...")
        try:
            from inference import EnhancedInferencePipeline
            self.pipeline = EnhancedInferencePipeline(models_dir=MODELS_DIR)
            self._initialized = True
            logger.info(" Inference pipeline initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize inference pipeline: {e}")
            raise
    
    def run_inference(self, csv_path: Path, output_path: Path, job_id: str) -> Dict[str, Any]:
        """
        Run inference on a CSV file
        
        Args:
            csv_path: Path to the input CSV
            output_path: Path to save JSON results
            job_id: Job identifier for tracking
            
        Returns:
            Dictionary with inference results and statistics
        """
        if not self._initialized:
            self.initialize()
        
        logger.info(f"[{job_id}] Starting model inference...")
        update_job_status(job_id, "inferencing", 70, "Running model inference...")
        
        try:
            # Run enhanced inference pipeline - returns tuple of (reports, metrics)
            results, evaluation_metrics = self.pipeline.generate_detailed_json_report(
                input_path=csv_path,
                output_path=output_path,
                include_layer_details=True,
                include_true_labels=False
            )
            
            # Calculate statistics
            total_flows = len(results)
            malicious_count = sum(1 for r in results if r['final_verdict'] == 'MALICIOUS')
            benign_count = total_flows - malicious_count
            detection_rate = (malicious_count / total_flows * 100) if total_flows > 0 else 0
            
            # Attack success analysis
            successful_attacks = sum(
                1 for r in results 
                if r.get('attack_execution_result', {}).get('attack_outcome') == 'SUCCESSFUL_ATTACK'
            )
            
            stats = {
                "total_flows": total_flows,
                "malicious_count": malicious_count,
                "benign_count": benign_count,
                "detection_rate": round(detection_rate, 2),
                "successful_attacks": successful_attacks,
                "attack_success_rate": round((successful_attacks / malicious_count * 100) if malicious_count > 0 else 0, 2)
            }
            
            logger.info(f"[{job_id}]  Inference complete - {malicious_count}/{total_flows} malicious detected")
            update_job_status(job_id, "inferencing", 90, "Saving to database...")
            
            # Read JSON file and store in database
            with open(output_path, 'r') as f:
                json_data = json.load(f)
            
            db.store_inference_results(
                job_id=job_id,
                json_data=json_data,
                original_filename=job_statuses.get(job_id, {}).get('filename'),
                json_file_path=str(output_path),
                csv_file_path=str(csv_path)
            )
            
            logger.info(f"[{job_id}]  Results stored in database")
            update_job_status(job_id, "inferencing", 95, "Finalizing results...")
            
            return {
                "stats": stats,
                "results": results,
                "csv_path": str(csv_path)
            }
            
        except Exception as e:
            logger.error(f"[{job_id}] Inference failed: {e}")
            raise

# ============================================================================
# STARTUP EVENT: Pre-load ML models for fast inference
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Pre-load ML models at server startup for fast inference"""
    global inference_engine
    
    logger.info("=" * 80)
    logger.info("PRE-LOADING ML MODELS AT STARTUP...")
    logger.info("=" * 80)
    
    try:
        # Import and initialize the inference engine
        # This loads all models once and keeps them in memory
        inference_engine = InferenceEngine()
        inference_engine.initialize()  # This loads all 4 model layers
        
        logger.info("=" * 80)
        logger.info("✓ ALL MODELS PRE-LOADED SUCCESSFULLY!")
        logger.info("  Inference will now be ~100x faster (no model loading per request)")
        logger.info("=" * 80)
    except Exception as e:
        logger.error(f"FAILED TO PRE-LOAD MODELS: {e}")
        logger.warning("Models will be loaded on first request (slower)")
        inference_engine = InferenceEngine()  # Create instance anyway, will lazy-load

# ============================================================================
# HELPER FUNCTIONS  
# ============================================================================

def update_job_status(
    job_id: str, 
    status: str, 
    progress: int, 
    message: str,
    error: str = None,
    result_file: str = None,
    stats: Dict = None
):
    """Update job status in the global status tracker and persist to disk"""
    if job_id in job_statuses:
        job_statuses[job_id].update({
            "status": status,
            "progress": progress,
            "message": message,
        })
        if error:
            job_statuses[job_id]["error"] = error
        if result_file:
            job_statuses[job_id]["result_file"] = result_file
            job_statuses[job_id]["completed_at"] = datetime.now().isoformat()
        if stats:
            job_statuses[job_id]["stats"] = stats
        
        # Persist to disk
        save_jobs()

def process_pcap_file(job_id: str, pcap_path: Path, original_filename: str):
    """Background task to process PCAP file by running main_pipeline.py"""
    import time
    import traceback
    import subprocess
    import json
    
    job_start_time = time.time()
    logger.info(f"[{job_id}] ========== JOB STARTED ==========")
    logger.info(f"[{job_id}] Original filename: {original_filename}")
    logger.info(f"[{job_id}] PCAP path: {pcap_path}")
    logger.info(f"[{job_id}] Job start time: {datetime.now().isoformat()}")
    
    # Initialize log list for job
    job_logs = []
    
    def log_and_store(level: str, message: str):
        """Log message and store in job logs"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {level}: {message}"
        job_logs.append(log_entry)
        if level == "ERROR":
            logger.error(f"[{job_id}] {message}")
        elif level == "WARNING":
            logger.warning(f"[{job_id}] {message}")
        else:
            logger.info(f"[{job_id}] {message}")
    
    try:
        # Create job-specific temp directory
        job_temp_dir = TEMP_DIR / job_id
        job_temp_dir.mkdir(parents=True, exist_ok=True)
        log_and_store("INFO", f"Created temp directory: {job_temp_dir}")
        
        # Prepare main_pipeline command using local repo path instead of hard-coded drive
        main_pipeline_script = BACKEND_DIR.parent / "pcap_to_csv" / "main_pipeline.py"

        if not main_pipeline_script.exists():
            raise FileNotFoundError(f"main_pipeline.py not found at {main_pipeline_script}")
        
        cmd = [
            sys.executable,  # Python interpreter
            str(main_pipeline_script),
            str(pcap_path),  # Input PCAP
            str(job_temp_dir),  # Output directory
            "--models-dir", str(MODELS_DIR),  # Models directory
            "--skip-inference"  # Skip inference in subprocess - use in-memory models instead!
        ]
        
        # Add labels if available (optional)
        labels_file = BACKEND_DIR.parent / "traffic_labels.jsonl"
        if labels_file.exists():
            cmd.extend(["--labels", str(labels_file)])
        
        log_and_store("INFO", f"Running pipeline: {' '.join(cmd)}")
        update_job_status(job_id, "processing", 5, "Starting PCAP processing pipeline...")
        
        # Run subprocess
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='ignore',
            bufsize=1
        )
        
        # Read stdout line by line
        current_progress = 5
        for line in process.stdout:
            line = line.strip()
            if not line:
                continue
            
            log_and_store("INFO", line)
            
            # Parse progress from output
            if "STEP 1/4" in line or "FLOW FEATURE EXTRACTION" in line:
                current_progress = 20
                update_job_status(job_id, "processing", current_progress, "Extracting flow features...")
            
            elif "Flow extraction complete" in line:
                current_progress = 35
                update_job_status(job_id, "processing", current_progress, "Flow features extracted")
            
            elif "STEP 2/4" in line or "PAYLOAD EXTRACTION" in line:
                current_progress = 40
                update_job_status(job_id, "converting", current_progress, "Extracting HTTP payloads...")
            
            elif "Payload extraction complete" in line:
                current_progress = 55
                update_job_status(job_id, "converting", current_progress, "Payloads extracted")
            
            elif "STEP 3/4" in line or "MERGING FEATURES" in line:
                current_progress = 60
                update_job_status(job_id, "converting", current_progress, "Merging features...")
            
            elif "Merge complete" in line:
                current_progress = 70
                update_job_status(job_id, "converting", current_progress, "Features merged")
            
            elif "STEP 4/4" in line or "MODEL INFERENCE" in line:
                current_progress = 75
                update_job_status(job_id, "inferencing", current_progress, "Running model inference...")
            
            elif "Inference complete" in line:
                current_progress = 95
                update_job_status(job_id, "inferencing", current_progress, "Inference complete")
            
            elif "PIPELINE COMPLETE" in line:
                current_progress = 98
                update_job_status(job_id, "inferencing", current_progress, "Finalizing results...")
        
        # Wait for process to complete
        returncode = process.wait()
        
        # Read stderr
        stderr_output = process.stderr.read()
        if stderr_output:
            log_and_store("WARNING", f"stderr output: {stderr_output}")
        
        # Check if process succeeded
        if returncode != 0:
            raise Exception(f"Pipeline failed with exit code {returncode}. Check logs for details.")
        
        log_and_store("INFO", "CSV conversion subprocess completed successfully")
        
        # Find output files in job_temp_dir (merged.csv only - we skipped inference)
        merged_csv = job_temp_dir / "merged.csv"
        results_json = job_temp_dir / "results.json"
        
        if not merged_csv.exists():
            raise FileNotFoundError(f"Expected merged CSV not found: {merged_csv}")
        
        # =========================================================================
        # RUN INFERENCE WITH IN-MEMORY MODELS (FAST!)
        # =========================================================================
        log_and_store("INFO", "Running inference with pre-loaded in-memory models...")
        update_job_status(job_id, "processing", 60, "Running model inference (using pre-loaded models)...")
        
        try:
            # Use the global inference engine (models already loaded at startup!)
            inference_result = inference_engine.run_inference(
                csv_path=merged_csv,
                output_path=results_json,
                job_id=job_id
            )
            log_and_store("INFO", f"Inference complete in memory: {inference_result.get('stats', {})}")
        except Exception as e:
            log_and_store("ERROR", f"In-memory inference failed: {e}")
            raise
        
        # Move results to RESULTS_DIR
        final_json = RESULTS_DIR / f"{job_id}_results.json"
        shutil.copy(str(results_json), str(final_json))
        log_and_store("INFO", f"Results copied to {final_json}")
        
        # Load and parse results for stats
        with open(final_json, 'r') as f:
            json_data = json.load(f)
        
        # Calculate statistics
        predictions = json_data.get('predictions', [])
        total_flows = len(predictions)
        malicious_count = sum(1 for p in predictions if p.get('final_verdict') == 'MALICIOUS')
        benign_count = total_flows - malicious_count
        detection_rate = (malicious_count / total_flows * 100) if total_flows > 0 else 0
        
        # Attack success analysis
        successful_attacks = sum(
            1 for p in predictions 
            if p.get('attack_execution_result', {}).get('attack_outcome') == 'SUCCESSFUL_ATTACK'
        )
        
        stats = {
            "total_flows": total_flows,
            "malicious_count": malicious_count,
            "benign_count": benign_count,
            "detection_rate": round(detection_rate, 2),
            "successful_attacks": successful_attacks,
            "attack_success_rate": round((successful_attacks / malicious_count * 100) if malicious_count > 0 else 0, 2)
        }
        
        log_and_store("INFO", f"Statistics: {stats}")
        
        # Store in database
        log_and_store("INFO", "Storing results in database...")
        db.store_inference_results(
            job_id=job_id,
            json_data=json_data,
            original_filename=original_filename,
            json_file_path=str(final_json),
            csv_file_path=str(merged_csv)
        )
        log_and_store("INFO", "Results stored in database")
        
        # Calculate total time
        total_time = time.time() - job_start_time
        log_and_store("INFO", f" JOB COMPLETE - Total time: {total_time:.2f}s")
        
        # Update job status with success
        update_job_status(
            job_id, 
            "completed", 
            100, 
            f"Analysis complete! Detected {malicious_count} malicious flows out of {total_flows} total.",
            result_file=str(final_json),
            stats=stats
        )
        
        # Store logs and CSV path in job status
        if job_id in job_statuses:
            job_statuses[job_id]["logs"] = job_logs
            job_statuses[job_id]["total_time_seconds"] = round(total_time, 2)
            job_statuses[job_id]["csv_file"] = str(merged_csv)  # Store CSV path for merged download
            job_statuses[job_id]["filename"] = original_filename
            save_jobs()
        
        logger.info(f"[{job_id}] ========== JOB COMPLETED SUCCESSFULLY ==========")
        
    except Exception as e:
        error_traceback = traceback.format_exc()
        log_and_store("ERROR", f"Processing failed: {str(e)}")
        log_and_store("ERROR", f"Traceback:\n{error_traceback}")
        
        logger.error(f"[{job_id}] ========== JOB FAILED ==========")
        logger.error(f"[{job_id}] Error: {e}")
        logger.error(f"[{job_id}] Full traceback:\n{error_traceback}")
        
        update_job_status(
            job_id,
            "failed",
            0,
            f"Processing failed: {str(e)}",
            error=str(e)
        )
        
        # Store logs and error in job status
        if job_id in job_statuses:
            job_statuses[job_id]["logs"] = job_logs
            job_statuses[job_id]["error_traceback"] = error_traceback
            save_jobs()
            
    finally:
        # Cleanup uploaded PCAP file
        if pcap_path.exists():
            try:
                os.remove(pcap_path)
                logger.debug(f"[{job_id}] Cleaned up uploaded PCAP file")
            except:
                pass
# Initialize the inference engine at startup (lazy)
inference_engine = InferenceEngine()

# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "message": "Hybrid IDS Inference API",
        "version": "1.0.0",
        "endpoints": {
            "upload": "/api/upload - POST a PCAP file for analysis",
            "status": "/api/status/{job_id} - GET job status",
            "results": "/api/results/{job_id} - GET inference results",
            "download": "/api/download/{job_id} - Download results as JSON file",
            "health": "/api/health - API health check"
        }
    }

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "models_dir": str(MODELS_DIR),
        "models_available": MODELS_DIR.exists()
    }

@app.post("/api/upload")
async def upload_pcap(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):
    """
    Upload a PCAP file for analysis
    
    The file will be processed asynchronously:
    1. PCAP → CSV conversion
    2. Model inference
    3. Results saved as JSON
    
    Returns a job_id to track progress
    """
    # Validate file extension
    allowed_extensions = ['.pcap', '.pcapng', '.cap']
    file_ext = Path(file.filename).suffix.lower()
    
    if file_ext not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Allowed: {', '.join(allowed_extensions)}"
        )
    
    # Generate job ID
    job_id = str(uuid.uuid4())[:8]
    
    # Save uploaded file
    upload_path = UPLOAD_DIR / f"{job_id}_{file.filename}"
    
    try:
        with open(upload_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save file: {e}")
    
    # Initialize job status
    job_statuses[job_id] = {
        "job_id": job_id,
        "status": "pending",
        "progress": 0,
        "message": "File uploaded, starting processing...",
        "created_at": datetime.now().isoformat(),
        "completed_at": None,
        "result_file": None,
        "error": None,
        "stats": None,
        "original_filename": file.filename
    }
    
    # Persist the new job
    save_jobs()
    
    # Start background processing
    background_tasks.add_task(process_pcap_file, job_id, upload_path, file.filename)
    
    logger.info(f"[{job_id}] PCAP upload received: {file.filename}")
    
    return {
        "job_id": job_id,
        "message": "File uploaded successfully. Processing started.",
        "status_url": f"/api/status/{job_id}",
        "filename": file.filename
    }

@app.get("/api/status/{job_id}")
async def get_job_status(job_id: str):
    """Get the status of a processing job"""
    if job_id not in job_statuses:
        raise HTTPException(status_code=404, detail="Job not found")
    
    return job_statuses[job_id]

@app.get("/api/results/{job_id}")
async def get_results(job_id: str):
    """Get the inference results for a completed job"""
    if job_id not in job_statuses:
        raise HTTPException(status_code=404, detail="Job not found")
    
    job = job_statuses[job_id]
    
    if job["status"] != "completed":
        raise HTTPException(
            status_code=400, 
            detail=f"Job not completed yet. Current status: {job['status']}"
        )
    
    result_file = Path(job["result_file"])
    if not result_file.exists():
        raise HTTPException(status_code=404, detail="Result file not found")
    
    try:
        with open(result_file, 'r') as f:
            results = json.load(f)
        
        return {
            "job_id": job_id,
            "stats": job["stats"],
            "total_results": len(results),
            "results": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read results: {e}")

@app.get("/api/download/{job_id}")
async def download_results(job_id: str):
    """Download the results JSON file"""
    if job_id not in job_statuses:
        raise HTTPException(status_code=404, detail="Job not found")
    
    job = job_statuses[job_id]
    
    if job["status"] != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Job not completed yet. Current status: {job['status']}"
        )
    
    result_file = Path(job["result_file"])
    if not result_file.exists():
        raise HTTPException(status_code=404, detail="Result file not found")
    
    # Create a user-friendly filename
    original_name = job.get("original_filename", "results")
    download_name = f"{Path(original_name).stem}_analysis_results.json"
    
    return FileResponse(
        path=result_file,
        filename=download_name,
        media_type="application/json"
    )

@app.get("/api/jobs")
async def list_jobs():
    """List all jobs and their statuses"""
    return {
        "total_jobs": len(job_statuses),
        "jobs": list(job_statuses.values())
    }

@app.delete("/api/jobs/{job_id}")
async def delete_job(job_id: str):
    """Delete a job and its associated files"""
    if job_id not in job_statuses:
        raise HTTPException(status_code=404, detail="Job not found")
    
    job = job_statuses[job_id]
    
    # Delete result file if exists
    if job.get("result_file"):
        result_path = Path(job["result_file"])
        if result_path.exists():
            os.remove(result_path)
    
    # Delete temp directory
    temp_dir = TEMP_DIR / job_id
    if temp_dir.exists():
        shutil.rmtree(temp_dir)
    
    # Remove from status tracker
    del job_statuses[job_id]
    
    return {"message": f"Job {job_id} deleted successfully"}

@app.get("/api/logs/{job_id}")
async def get_job_logs(job_id: str):
    """Get logs for a specific job"""
    if job_id not in job_statuses:
        raise HTTPException(status_code=404, detail="Job not found")
    
    job = job_statuses[job_id]
    
    return {
        "job_id": job_id,
        "status": job.get("status"),
        "progress": job.get("progress"),
        "message": job.get("message"),
        "error": job.get("error"),
        "error_traceback": job.get("error_traceback"),
        "logs": job.get("logs", []),
        "total_time_seconds": job.get("total_time_seconds")
    }

@app.get("/api/server-logs")
async def get_server_logs(lines: int = 100):
    """Get the last N lines from the server log file"""
    try:
        if LOG_FILE.exists():
            with open(LOG_FILE, 'r', encoding='utf-8') as f:
                all_lines = f.readlines()
                last_lines = all_lines[-lines:] if len(all_lines) > lines else all_lines
                return {
                    "log_file": str(LOG_FILE),
                    "total_lines": len(all_lines),
                    "showing_lines": len(last_lines),
                    "logs": [line.strip() for line in last_lines]
                }
        else:
            return {
                "log_file": str(LOG_FILE),
                "error": "Log file not found",
                "logs": []
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read logs: {e}")

# ============================================================================
# ADDITIONAL ENDPOINTS FOR FRONTEND COMPATIBILITY
# ============================================================================

@app.get("/api/kpi/summary")
async def kpi_summary(time_range: str = "24h"):
    """Get KPI summary for dashboard"""
    # Aggregate stats from all completed jobs
    completed_jobs = [j for j in job_statuses.values() if j["status"] == "completed" and j.get("stats")]
    
    total_flows = sum(j["stats"]["total_flows"] for j in completed_jobs)
    total_malicious = sum(j["stats"]["malicious_count"] for j in completed_jobs)
    total_benign = sum(j["stats"]["benign_count"] for j in completed_jobs)
    
    return {
        "total_packets_analyzed": total_flows,
        "malicious_detected": total_malicious,
        "benign_detected": total_benign,
        "detection_rate": round((total_malicious / total_flows * 100) if total_flows > 0 else 0, 2),
        "jobs_completed": len(completed_jobs),
        "time_range": time_range
    }

@app.get("/api/layers/statistics")
async def layer_statistics(time_range: str = "24h"):
    """Get layer-by-layer detection statistics"""
    return {
        "signature_filter": {"detections": 0, "confidence_avg": 0},
        "autoencoder": {"anomalies": 0, "avg_error": 0},
        "bilstm": {"malicious": 0, "confidence_avg": 0},
        "meta_classifier": {"final_malicious": 0, "accuracy": 0},
        "time_range": time_range
    }

# ============================================================================
# MERGED CSV DOWNLOAD ENDPOINT
# ============================================================================

@app.get("/api/download-merged-csv/{job_id}")
async def download_merged_csv(job_id: str):
    """
    Download merged CSV combining original features with inference predictions.
    This merges the tshark-extracted features with model predictions.
    """
    if job_id not in job_statuses:
        raise HTTPException(status_code=404, detail="Job not found")
    
    job = job_statuses[job_id]
    
    if job["status"] != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Job not completed yet. Current status: {job['status']}"
        )
    
    # Get CSV file path from job status
    csv_file = job.get("csv_file")
    if not csv_file or not Path(csv_file).exists():
        raise HTTPException(status_code=404, detail="CSV file not found")
    
    # Get JSON results path
    result_file = job.get("result_file")
    if not result_file or not Path(result_file).exists():
        raise HTTPException(status_code=404, detail="Results file not found")
    
    try:
        # Load original CSV (tshark features)
        original_df = pd.read_csv(csv_file)
        
        # Load JSON predictions
        with open(result_file, 'r') as f:
            json_data = json.load(f)
        
        predictions = json_data.get('predictions', [])
        
        # Create predictions DataFrame
        pred_records = []
        for pred in predictions:
            attack_class = pred.get('attack_classification', {})
            attack_result = pred.get('attack_execution_result', {})
            layer1 = pred.get('layer_details', {}).get('layer_1_signature', {})
            layer2 = pred.get('layer_details', {}).get('layer_2_autoencoder', {})
            layer3 = pred.get('layer_details', {}).get('layer_3_bilstm', {})
            
            pred_records.append({
                'prediction_verdict': pred.get('final_verdict'),
                'prediction_confidence': pred.get('confidence_score'),
                'attack_type': attack_class.get('attack_type'),
                'attack_subtype': attack_class.get('subtype'),
                'attack_severity': attack_class.get('severity'),
                'attack_outcome': attack_result.get('attack_outcome'),
                'success_confidence': attack_result.get('success_confidence'),
                'layer1_detected': layer1.get('detected'),
                'layer1_pattern': layer1.get('pattern'),
                'layer1_confidence': layer1.get('confidence'),
                'layer2_status': layer2.get('status'),
                'layer2_reconstruction_error': layer2.get('reconstruction_error'),
                'layer2_anomaly_score': layer2.get('anomaly_score'),
                'layer3_detected': layer3.get('detected'),
                'layer3_prob_malicious': layer3.get('prob_malicious'),
                'layer3_confidence': layer3.get('confidence')
            })
        
        pred_df = pd.DataFrame(pred_records)
        
        # Merge original features with predictions
        # Reset indices to ensure proper alignment
        original_df = original_df.reset_index(drop=True)
        pred_df = pred_df.reset_index(drop=True)
        
        # Check if lengths match
        if len(original_df) != len(pred_df):
            logger.warning(f"Row mismatch: CSV has {len(original_df)} rows, predictions have {len(pred_df)} rows")
            # Use minimum length
            min_len = min(len(original_df), len(pred_df))
            original_df = original_df.iloc[:min_len]
            pred_df = pred_df.iloc[:min_len]
        
        # Merge DataFrames
        merged_df = pd.concat([original_df, pred_df], axis=1)
        
        # Save merged CSV to temp file
        merged_csv_path = RESULTS_DIR / f"{job_id}_merged.csv"
        merged_df.to_csv(merged_csv_path, index=False)
        
        # Create user-friendly filename
        original_name = job.get("original_filename", "results")
        download_name = f"{Path(original_name).stem}_merged_features.csv"
        
        logger.info(f"[{job_id}]  Created merged CSV with {len(merged_df)} rows and {len(merged_df.columns)} columns")
        
        return FileResponse(
            path=merged_csv_path,
            filename=download_name,
            media_type="text/csv"
        )
        
    except Exception as e:
        logger.error(f"[{job_id}] Failed to create merged CSV: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create merged CSV: {str(e)}")

# ============================================================================
# DATABASE QUERY ENDPOINTS (for visualizations)
# ============================================================================

@app.get("/api/db/jobs")
async def get_db_jobs(limit: int = 50):
    """Get all jobs from database with summary stats"""
    try:
        jobs = db.get_all_jobs(limit=limit)
        return {"jobs": jobs, "total": len(jobs)}
    except Exception as e:
        logger.error(f"Failed to get jobs from database: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/db/job/{job_id}")
async def get_db_job_summary(job_id: str):
    """Get summary for a specific job from database"""
    try:
        summary = db.get_job_summary(job_id)
        if not summary:
            raise HTTPException(status_code=404, detail="Job not found in database")
        return summary
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get job summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/db/predictions/{job_id}")
async def get_db_predictions(
    job_id: str,
    verdict: str = None,
    attack_type: str = None,
    limit: int = 0,
    offset: int = 0
):
    """Get predictions for a job from database with optional filtering. limit=0 means no limit."""
    try:
        predictions = db.get_predictions(
            job_id=job_id,
            verdict=verdict,
            attack_type=attack_type,
            limit=limit,
            offset=offset
        )
        return {"predictions": predictions, "count": len(predictions)}
    except Exception as e:
        logger.error(f"Failed to get predictions: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/db/attack-stats/{job_id}")
async def get_db_attack_stats(job_id: str):
    """Get attack type statistics for a job"""
    try:
        stats = db.get_attack_type_stats(job_id)
        return {"attack_stats": stats}
    except Exception as e:
        logger.error(f"Failed to get attack stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/db/attack-stats")
async def get_all_attack_stats():
    """Get overall attack type statistics across all jobs"""
    try:
        stats = db.get_attack_type_stats()
        return {"attack_stats": stats}
    except Exception as e:
        logger.error(f"Failed to get attack stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# VISUALIZATION ENDPOINTS FOR DASHBOARD
# ============================================================================

@app.get("/api/dashboard/summary/{job_id}")
async def get_dashboard_summary(job_id: str):
    """Get comprehensive dashboard summary for a specific job"""
    try:
        # Get job summary from database
        summary = db.get_job_summary(job_id)
        if not summary:
            raise HTTPException(status_code=404, detail="Job not found in database")
        
        # Get attack stats
        attack_stats = db.get_attack_type_stats(job_id)
        
        # Get predictions for layer analysis (ALL predictions, no limit)
        predictions = db.get_predictions(job_id)
        
        # Calculate layer statistics
        layer_stats = {
            "signature_filter": {"triggered": 0, "confidence_avg": 0},
            "autoencoder": {"anomalies": 0, "avg_error": 0},
            "bilstm": {"malicious": 0, "confidence_avg": 0},
            "meta_classifier": {"total": 0, "accuracy": 0}
        }
        
        # Count verdicts
        verdicts = {"MALICIOUS": 0, "BENIGN": 0}
        for p in predictions:
            verdict = p.get("final_verdict", "BENIGN")
            verdicts[verdict] = verdicts.get(verdict, 0) + 1
        
        return {
            "job_id": job_id,
            "summary": summary,
            "attack_stats": attack_stats,
            "verdicts": verdicts,
            "layer_stats": layer_stats,
            "total_predictions": len(predictions)
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get dashboard summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/dashboard/flow-analysis/{job_id}")
async def get_flow_analysis(job_id: str):
    """Get flow-level analysis data for visualizations"""
    try:
        # Read merged CSV for flow data
        temp_dir = TEMP_DIR / job_id
        merged_csv = temp_dir / "merged.csv"
        
        if not merged_csv.exists():
            raise HTTPException(status_code=404, detail="Merged CSV not found")
        
        df = pd.read_csv(merged_csv)
        
        # HTTP Methods distribution
        method_counts = {}
        if 'method' in df.columns:
            method_counts = df['method'].value_counts().head(10).to_dict()
        
        # Top hosts
        host_counts = {}
        if 'host' in df.columns:
            host_counts = df['host'].value_counts().head(10).to_dict()
        
        # URI patterns
        uri_counts = {}
        if 'uri' in df.columns:
            # Get top 10 URIs (truncate long ones)
            df['uri_short'] = df['uri'].str[:50]
            uri_counts = df['uri_short'].value_counts().head(10).to_dict()
        
        # Flow statistics
        flow_stats = {
            "total_flows": len(df),
            "avg_flow_duration": float(df['flow_duration'].mean()) if 'flow_duration' in df.columns else 0,
            "max_flow_duration": float(df['flow_duration'].max()) if 'flow_duration' in df.columns else 0,
            "avg_packet_length": float(df['pkt_len_mean'].mean()) if 'pkt_len_mean' in df.columns else 0,
            "http_flows": int(df['has_http_payload'].sum()) if 'has_http_payload' in df.columns else 0,
        }
        
        # Source IPs
        src_ip_counts = {}
        if 'src_ip' in df.columns:
            src_ip_counts = df['src_ip'].value_counts().head(10).to_dict()
        
        # Destination IPs
        dst_ip_counts = {}
        if 'dst_ip' in df.columns:
            dst_ip_counts = df['dst_ip'].value_counts().head(10).to_dict()
        
        # User agents
        user_agent_counts = {}
        if 'user_agent' in df.columns:
            df['ua_short'] = df['user_agent'].astype(str).str[:40]
            user_agent_counts = df['ua_short'].value_counts().head(10).to_dict()
        
        # Content types
        content_type_counts = {}
        if 'content_type' in df.columns:
            content_type_counts = df['content_type'].value_counts().head(10).to_dict()
        
        return {
            "job_id": job_id,
            "method_distribution": method_counts,
            "host_distribution": host_counts,
            "uri_distribution": uri_counts,
            "flow_stats": flow_stats,
            "src_ip_distribution": src_ip_counts,
            "dst_ip_distribution": dst_ip_counts,
            "user_agent_distribution": user_agent_counts,
            "content_type_distribution": content_type_counts
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get flow analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/dashboard/layer-details/{job_id}")
async def get_layer_details(job_id: str):
    """Get detailed layer-by-layer analysis from predictions"""
    try:
        predictions = db.get_predictions(job_id, limit=10000)
        
        if not predictions:
            raise HTTPException(status_code=404, detail="No predictions found")
        
        # Analyze each layer
        signature_results = {"matched": 0, "patterns": {}}
        autoencoder_results = {"anomalies": 0, "reconstruction_errors": []}
        bilstm_results = {"malicious": 0, "benign": 0, "confidences": []}
        meta_results = {"malicious": 0, "benign": 0, "attack_types": {}}
        
        for p in predictions:
            # Signature filter
            if p.get("signature_matched"):
                signature_results["matched"] += 1
            
            # Final verdict
            if p.get("final_verdict") == "MALICIOUS":
                meta_results["malicious"] += 1
            else:
                meta_results["benign"] += 1
            
            # Attack types
            attack_type = p.get("predicted_attack_type", "unknown")
            if attack_type and attack_type != "unknown":
                meta_results["attack_types"][attack_type] = meta_results["attack_types"].get(attack_type, 0) + 1
        
        return {
            "job_id": job_id,
            "total_predictions": len(predictions),
            "signature_filter": {
                "total_matched": signature_results["matched"],
                "match_rate": round(signature_results["matched"] / len(predictions) * 100, 2) if predictions else 0
            },
            "autoencoder": {
                "anomalies_detected": autoencoder_results["anomalies"],
                "anomaly_rate": round(autoencoder_results["anomalies"] / len(predictions) * 100, 2) if predictions else 0
            },
            "bilstm": {
                "malicious_detected": bilstm_results["malicious"],
                "benign_detected": bilstm_results["benign"],
                "detection_rate": round(bilstm_results["malicious"] / len(predictions) * 100, 2) if predictions else 0
            },
            "meta_classifier": {
                "total_malicious": meta_results["malicious"],
                "total_benign": meta_results["benign"],
                "attack_type_distribution": meta_results["attack_types"],
                "detection_rate": round(meta_results["malicious"] / len(predictions) * 100, 2) if predictions else 0
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get layer details: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/dashboard/timeline/{job_id}")
async def get_timeline_data(job_id: str):
    """Get timeline data for visualizing attack patterns over time"""
    try:
        predictions = db.get_predictions(job_id, limit=10000)
        
        if not predictions:
            return {"job_id": job_id, "timeline": []}
        
        # Group by attack type for timeline
        timeline_data = []
        malicious_count = 0
        benign_count = 0
        
        # Since we don't have timestamps in current data, create synthetic timeline
        for i, p in enumerate(predictions):
            is_malicious = p.get("final_verdict") == "MALICIOUS"
            if is_malicious:
                malicious_count += 1
            else:
                benign_count += 1
            
            # Group every 100 predictions
            if (i + 1) % 100 == 0 or i == len(predictions) - 1:
                timeline_data.append({
                    "batch": (i // 100) + 1,
                    "malicious": malicious_count,
                    "benign": benign_count,
                    "total": i + 1
                })
        
        return {
            "job_id": job_id,
            "timeline": timeline_data,
            "total_malicious": sum(1 for p in predictions if p.get("final_verdict") == "MALICIOUS"),
            "total_benign": sum(1 for p in predictions if p.get("final_verdict") != "MALICIOUS")
        }
    except Exception as e:
        logger.error(f"Failed to get timeline data: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/dashboard/attack-stats/{job_id}")
async def get_attack_stats(job_id: str):
    """
    Get attack attempted vs successful statistics from DATABASE.
    
    Attack Attempted: Layer 1 detected OR Layer 2 reconstruction_error > threshold
    Attack Successful: final_verdict == MALICIOUS
    Attack Blocked: Attempted - Successful
    Benign Traffic: Total - Attempted
    """
    try:
        # Get ALL predictions from database (no limit)
        predictions = db.get_predictions(job_id)
        
        if not predictions:
            return {
                "job_id": job_id,
                "total_predictions": 0,
                "attacks_attempted": 0,
                "attacks_successful": 0,
                "attacks_blocked": 0,
                "benign_traffic": 0,
                "attempt_rate": 0.0,
                "success_rate": 0.0
            }
        
        total = len(predictions)
        
        # Calculate threshold (99th percentile of reconstruction errors)
        reconstruction_errors = [p.get('layer2_reconstruction_error', 0) for p in predictions if p.get('layer2_reconstruction_error') is not None]
        if reconstruction_errors:
            sorted_errors = sorted(reconstruction_errors)
            threshold_idx = int(len(sorted_errors) * 0.99)
            threshold = sorted_errors[min(threshold_idx, len(sorted_errors) - 1)]
        else:
            threshold = 0.001  # Default threshold
        
        attacks_attempted = 0
        attacks_successful = 0
        
        for pred in predictions:
            # Check if attack was ATTEMPTED
            # Layer 1: Signature detected
            layer1_detected = pred.get('layer1_detected', 0) == 1
            
            # Layer 2: Reconstruction error > threshold
            layer2_error = pred.get('layer2_reconstruction_error', 0) or 0
            layer2_anomaly = layer2_error > threshold
            
            is_attempted = layer1_detected or layer2_anomaly
            
            if is_attempted:
                attacks_attempted += 1
            
            # Check if attack was SUCCESSFUL (final verdict is MALICIOUS)
            final_verdict = pred.get('final_verdict', 'BENIGN')
            if final_verdict == 'MALICIOUS':
                attacks_successful += 1
        
        # Calculate derived stats
        attacks_blocked = attacks_attempted - attacks_successful
        benign_traffic = total - attacks_attempted
        
        # Ensure blocked is not negative
        attacks_blocked = max(0, attacks_blocked)
        benign_traffic = max(0, benign_traffic)
        
        attempt_rate = round((attacks_attempted / total) * 100, 2) if total > 0 else 0.0
        success_rate = round((attacks_successful / attacks_attempted) * 100, 2) if attacks_attempted > 0 else 0.0
        
        return {
            "job_id": job_id,
            "total_predictions": total,
            "attacks_attempted": attacks_attempted,
            "attacks_successful": attacks_successful,
            "attacks_blocked": attacks_blocked,
            "benign_traffic": benign_traffic,
            "attempt_rate": attempt_rate,
            "success_rate": success_rate,
            "threshold_used": round(threshold, 6)
        }
        
    except Exception as e:
        logger.error(f"Failed to get attack stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/dashboard/severity-heatmap/{job_id}")
async def get_severity_heatmap(job_id: str):
    """
    Get heatmap data for attack types vs severity levels.
    Returns counts for each (attack_type, severity) pair.
    """
    try:
        # Get results from the JSON file
        result_file = RESULTS_DIR / f"{job_id}_results.json"
        
        if not result_file.exists():
            raise HTTPException(status_code=404, detail="Results file not found")
        
        with open(result_file, 'r') as f:
            data = json.load(f)
        
        predictions = data.get('predictions', [])
        
        if not predictions:
            return {
                "job_id": job_id,
                "heatmap_data": [],
                "attack_types": [],
                "severity_levels": list(range(1, 11)),
                "max_count": 0
            }
        
        # Count occurrences of each (attack_type, severity) pair
        heatmap_counts = {}
        attack_types_set = set()
        
        for pred in predictions:
            attack_class = pred.get('attack_classification', {})
            attack_type = attack_class.get('attack_type', 'unknown')
            severity = attack_class.get('severity', 0)
            
            # Ensure severity is in valid range
            severity = max(0, min(10, int(severity) if severity else 0))
            
            if attack_type and attack_type != 'unknown':
                attack_types_set.add(attack_type)
                key = (attack_type, severity)
                heatmap_counts[key] = heatmap_counts.get(key, 0) + 1
        
        # Convert to list format for frontend
        heatmap_data = []
        max_count = 0
        
        for (attack_type, severity), count in heatmap_counts.items():
            heatmap_data.append({
                "attack_type": attack_type,
                "severity": severity,
                "count": count
            })
            max_count = max(max_count, count)
        
        # Sort attack types alphabetically
        attack_types = sorted(list(attack_types_set))
        
        return {
            "job_id": job_id,
            "heatmap_data": heatmap_data,
            "attack_types": attack_types,
            "severity_levels": list(range(0, 11)),
            "max_count": max_count
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get severity heatmap: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================================
# AUTOENCODER ANALYSIS ENDPOINT
# ============================================================================

@app.get("/api/dashboard/autoencoder-stats/{job_id}")
async def get_autoencoder_stats(job_id: str):
    """
    Get detailed autoencoder statistics for Layer 2 visualization.
    
    Returns reconstruction error distribution, threshold comparison,
    and anomaly detection breakdown.
    """
    try:
        predictions = db.get_predictions(job_id, limit=10000)
        
        if not predictions:
            raise HTTPException(status_code=404, detail="No predictions found")
        
        # Extract autoencoder data
        reconstruction_errors = []
        
        for p in predictions:
            error = p.get("layer2_reconstruction_error", 0)
            if error is not None:
                reconstruction_errors.append(float(error))
        
        # Calculate statistics and threshold first
        if reconstruction_errors:
            errors_array = reconstruction_errors
            mean_error = sum(errors_array) / len(errors_array)
            sorted_errors = sorted(errors_array)
            median_error = sorted_errors[len(sorted_errors) // 2]
            min_error = min(errors_array)
            max_error = max(errors_array)
            
            # Calculate threshold (99th percentile of errors)
            threshold_idx = int(len(sorted_errors) * 0.99)
            estimated_threshold = sorted_errors[min(threshold_idx, len(sorted_errors) - 1)]
            
            # NOW count anomalies based on reconstruction_error > threshold
            anomaly_count = sum(1 for e in errors_array if e > estimated_threshold)
            normal_count = len(errors_array) - anomaly_count
            
            # Create histogram buckets for error distribution
            num_buckets = 20
            bucket_size = (max_error - min_error) / num_buckets if max_error > min_error else 1
            error_distribution = []
            for i in range(num_buckets):
                bucket_min = min_error + i * bucket_size
                bucket_max = bucket_min + bucket_size
                count = sum(1 for e in errors_array if bucket_min <= e < bucket_max)
                error_distribution.append({
                    "range_min": round(bucket_min, 6),
                    "range_max": round(bucket_max, 6),
                    "count": count,
                    "is_above_threshold": bucket_min >= estimated_threshold
                })
        else:
            mean_error = 0
            median_error = 0
            min_error = 0
            max_error = 0
            estimated_threshold = 0
            error_distribution = []
            anomaly_count = 0
            normal_count = 0
        
        # Sample reconstruction errors for line chart (max 100 points)
        sample_size = min(100, len(reconstruction_errors))
        step = max(1, len(reconstruction_errors) // sample_size)
        sampled_errors = [
            {"index": i + 1, "error": round(reconstruction_errors[i * step], 6)}
            for i in range(sample_size) if i * step < len(reconstruction_errors)
        ]
        
        return {
            "job_id": job_id,
            "total_samples": len(predictions),
            "anomaly_count": anomaly_count,
            "normal_count": normal_count,
            "anomaly_rate": round(anomaly_count / len(predictions) * 100, 2) if predictions else 0,
            "threshold": round(estimated_threshold, 6),
            "statistics": {
                "mean_error": round(mean_error, 6),
                "median_error": round(median_error, 6),
                "min_error": round(min_error, 6),
                "max_error": round(max_error, 6)
            },
            "error_distribution": error_distribution,
            "sampled_errors": sampled_errors,
            "detection_logic": {
                "description": "Traffic is flagged as ANOMALY when reconstruction error exceeds threshold",
                "formula": "IF reconstruction_error > threshold THEN ANOMALY ELSE NORMAL"
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get autoencoder stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================


if __name__ == "__main__":
    import uvicorn
    
    print("=" * 80)
    print("HYBRID IDS INFERENCE API SERVER")
    print("=" * 80)
    print(f"\nBackend Directory: {BACKEND_DIR}")
    print(f"Models Directory: {MODELS_DIR}")
    print(f"Upload Directory: {UPLOAD_DIR}")
    print(f"Results Directory: {RESULTS_DIR}")
    print("\nStarting server...")
    print("=" * 80)
    
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
