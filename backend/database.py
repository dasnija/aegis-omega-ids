"""
SQLite Database Module for Hybrid IDS Inference Results
Stores metadata, evaluation metrics, and predictions from model inference.
"""

import sqlite3
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
import pandas as pd

logger = logging.getLogger(__name__)

# Database file path
DB_PATH = Path(__file__).parent / "ids_results.db"


def get_connection():
    """Get database connection with row factory for dict-like access"""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_database():
    """Initialize the database with required tables"""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Create jobs table - stores overall job info and metadata
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            original_filename TEXT,
            status TEXT DEFAULT 'pending',
            total_samples INTEGER,
            malicious_detected INTEGER,
            benign_detected INTEGER,
            has_ground_truth BOOLEAN,
            json_file_path TEXT,
            csv_file_path TEXT
        )
    ''')
    
    # Create evaluation_metrics table - stores per-job metrics
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS evaluation_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id TEXT NOT NULL,
            accuracy REAL,
            precision_score REAL,
            recall REAL,
            f1_score REAL,
            confusion_matrix TEXT,
            is_multiclass BOOLEAN,
            num_classes INTEGER,
            specificity REAL,
            sensitivity REAL,
            roc_auc REAL,
            classification_report TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (job_id) REFERENCES jobs(job_id) ON DELETE CASCADE
        )
    ''')
    
    # Create predictions table - stores individual packet predictions
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id TEXT NOT NULL,
            packet_id TEXT,
            final_verdict TEXT,
            confidence_score REAL,
            attack_type TEXT,
            attack_subtype TEXT,
            attack_severity INTEGER,
            attack_detected BOOLEAN,
            attack_outcome TEXT,
            success_confidence REAL,
            reasoning TEXT,
            layer1_detected BOOLEAN,
            layer1_pattern TEXT,
            layer1_confidence REAL,
            layer2_status TEXT,
            layer2_reconstruction_error REAL,
            layer2_anomaly_score REAL,
            layer3_detected BOOLEAN,
            layer3_prob_malicious REAL,
            layer3_confidence REAL,
            flow_duration REAL,
            tot_bwd_pkts INTEGER,
            totlen_bwd_pkts INTEGER,
            rst_flag_cnt INTEGER,
            fin_flag_cnt INTEGER,
            full_url TEXT,
            method TEXT,
            host TEXT,
            uri TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (job_id) REFERENCES jobs(job_id) ON DELETE CASCADE
        )
    ''')
    
    # Create indexes for faster queries
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_predictions_job_id ON predictions(job_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_predictions_verdict ON predictions(final_verdict)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_predictions_attack_type ON predictions(attack_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status)')
    
    conn.commit()
    conn.close()
    logger.info(" Database initialized successfully")


def store_inference_results(job_id: str, json_data: Dict[str, Any], 
                           original_filename: str = None,
                           json_file_path: str = None,
                           csv_file_path: str = None) -> bool:
    """
    Store inference results from JSON into the database.
    
    Args:
        job_id: Unique job identifier
        json_data: The complete inference JSON data
        original_filename: Original PCAP filename
        json_file_path: Path to saved JSON file
        csv_file_path: Path to merged CSV file
        
    Returns:
        True if successful, False otherwise
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        metadata = json_data.get('metadata', {})
        eval_metrics = json_data.get('evaluation_metrics', {})
        predictions = json_data.get('predictions', [])
        
        # Insert or update job metadata
        cursor.execute('''
            INSERT OR REPLACE INTO jobs 
            (job_id, completed_at, original_filename, status, 
             total_samples, malicious_detected, benign_detected, 
             has_ground_truth, json_file_path, csv_file_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            job_id,
            datetime.now().isoformat(),
            original_filename,
            'completed',
            metadata.get('total_samples', 0),
            metadata.get('malicious_detected', 0),
            metadata.get('benign_detected', 0),
            metadata.get('has_ground_truth', False),
            json_file_path,
            csv_file_path
        ))
        
        # Insert evaluation metrics
        cursor.execute('''
            INSERT INTO evaluation_metrics 
            (job_id, accuracy, precision_score, recall, f1_score, 
             confusion_matrix, is_multiclass, num_classes, 
             specificity, sensitivity, roc_auc, classification_report)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            job_id,
            eval_metrics.get('accuracy', 0),
            eval_metrics.get('precision', 0),
            eval_metrics.get('recall', 0),
            eval_metrics.get('f1_score', 0),
            json.dumps(eval_metrics.get('confusion_matrix', [])),
            eval_metrics.get('is_multiclass', False),
            eval_metrics.get('num_classes', 2),
            eval_metrics.get('specificity'),
            eval_metrics.get('sensitivity', 0),
            eval_metrics.get('roc_auc'),
            json.dumps(eval_metrics.get('classification_report', {}))
        ))
        
        # Insert predictions in batches
        for pred in predictions:
            attack_class = pred.get('attack_classification', {})
            attack_result = pred.get('attack_execution_result', {})
            layer_details = pred.get('layer_details', {})
            layer1 = layer_details.get('layer_1_signature', {})
            layer2 = layer_details.get('layer_2_autoencoder', {})
            layer3 = layer_details.get('layer_3_bilstm', {})
            network = pred.get('network_evidence', {})
            original = pred.get('original_data', {})
            
            cursor.execute('''
                INSERT INTO predictions 
                (job_id, packet_id, final_verdict, confidence_score,
                 attack_type, attack_subtype, attack_severity,
                 attack_detected, attack_outcome, success_confidence, reasoning,
                 layer1_detected, layer1_pattern, layer1_confidence,
                 layer2_status, layer2_reconstruction_error, layer2_anomaly_score,
                 layer3_detected, layer3_prob_malicious, layer3_confidence,
                 flow_duration, tot_bwd_pkts, totlen_bwd_pkts, rst_flag_cnt, fin_flag_cnt,
                 full_url, method, host, uri)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                job_id,
                pred.get('packet_id'),
                pred.get('final_verdict'),
                pred.get('confidence_score', 0),
                attack_class.get('attack_type'),
                attack_class.get('subtype'),
                attack_class.get('severity'),
                attack_result.get('attack_detected', False),
                attack_result.get('attack_outcome'),
                attack_result.get('success_confidence', 0),
                json.dumps(attack_result.get('reasoning', [])),
                layer1.get('detected', False),
                layer1.get('pattern'),
                layer1.get('confidence', 0),
                layer2.get('status'),
                layer2.get('reconstruction_error', 0),
                layer2.get('anomaly_score', 0),
                layer3.get('detected', False),
                layer3.get('prob_malicious', 0),
                layer3.get('confidence', 0),
                network.get('flow_duration', 0),
                network.get('tot_bwd_pkts', 0),
                network.get('totlen_bwd_pkts', 0),
                network.get('rst_flag_cnt', 0),
                network.get('fin_flag_cnt', 0),
                original.get('full_url'),
                original.get('method'),
                original.get('host'),
                original.get('uri')
            ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"[{job_id}] Stored {len(predictions)} predictions to database")
        return True
        
    except Exception as e:
        logger.error(f"[{job_id}] Failed to store results in database: {e}")
        return False


def get_job_summary(job_id: str) -> Optional[Dict[str, Any]]:
    """Get summary data for a job"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM jobs WHERE job_id = ?', (job_id,))
    job = cursor.fetchone()
    
    if not job:
        conn.close()
        return None
    
    cursor.execute('SELECT * FROM evaluation_metrics WHERE job_id = ?', (job_id,))
    metrics = cursor.fetchone()
    
    conn.close()
    
    return {
        'job': dict(job) if job else None,
        'metrics': dict(metrics) if metrics else None
    }


def get_predictions(job_id: str, 
                   verdict: str = None,
                   attack_type: str = None,
                   limit: int = 0,
                   offset: int = 0) -> List[Dict[str, Any]]:
    """Get predictions for a job with optional filtering. limit=0 means no limit."""
    conn = get_connection()
    cursor = conn.cursor()
    
    query = 'SELECT * FROM predictions WHERE job_id = ?'
    params = [job_id]
    
    if verdict:
        query += ' AND final_verdict = ?'
        params.append(verdict)
    
    if attack_type:
        query += ' AND attack_type = ?'
        params.append(attack_type)
    
    # Only add LIMIT if limit > 0
    if limit > 0:
        query += ' LIMIT ? OFFSET ?'
        params.extend([limit, offset])
    elif offset > 0:
        # If only offset is specified, we still need a limit for OFFSET to work
        query += ' LIMIT -1 OFFSET ?'
        params.append(offset)
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]


def get_predictions_as_dataframe(job_id: str) -> pd.DataFrame:
    """Get all predictions for a job as a pandas DataFrame"""
    conn = get_connection()
    df = pd.read_sql_query(
        'SELECT * FROM predictions WHERE job_id = ?', 
        conn, 
        params=(job_id,)
    )
    conn.close()
    return df


def get_all_jobs(limit: int = 50) -> List[Dict[str, Any]]:
    """Get all jobs with summary stats"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT j.*, 
               e.accuracy, e.precision_score, e.recall, e.f1_score
        FROM jobs j
        LEFT JOIN evaluation_metrics e ON j.job_id = e.job_id
        ORDER BY j.created_at DESC
        LIMIT ?
    ''', (limit,))
    
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]


def get_attack_type_stats(job_id: str = None) -> List[Dict[str, Any]]:
    """Get attack type statistics, optionally filtered by job"""
    conn = get_connection()
    cursor = conn.cursor()
    
    if job_id:
        cursor.execute('''
            SELECT attack_type, COUNT(*) as count, 
                   AVG(confidence_score) as avg_confidence,
                   SUM(CASE WHEN final_verdict = 'MALICIOUS' THEN 1 ELSE 0 END) as malicious_count
            FROM predictions 
            WHERE job_id = ? AND attack_type IS NOT NULL
            GROUP BY attack_type
            ORDER BY count DESC
        ''', (job_id,))
    else:
        cursor.execute('''
            SELECT attack_type, COUNT(*) as count,
                   AVG(confidence_score) as avg_confidence,
                   SUM(CASE WHEN final_verdict = 'MALICIOUS' THEN 1 ELSE 0 END) as malicious_count
            FROM predictions 
            WHERE attack_type IS NOT NULL
            GROUP BY attack_type
            ORDER BY count DESC
        ''')
    
    rows = cursor.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]


def delete_job(job_id: str) -> bool:
    """Delete a job and all related data"""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        # Delete related data (cascade should handle this, but be explicit)
        cursor.execute('DELETE FROM predictions WHERE job_id = ?', (job_id,))
        cursor.execute('DELETE FROM evaluation_metrics WHERE job_id = ?', (job_id,))
        cursor.execute('DELETE FROM jobs WHERE job_id = ?', (job_id,))
        
        conn.commit()
        conn.close()
        
        logger.info(f"[{job_id}] Deleted job from database")
        return True
        
    except Exception as e:
        logger.error(f"[{job_id}] Failed to delete job from database: {e}")
        return False


# Initialize database on module load
init_database()
