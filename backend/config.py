# config.py
"""
Configuration Module for Hybrid Intrusion Detection System (IDS)

This module contains all configuration parameters, file paths, hyperparameters,
blocklists, and feature definitions for the three-layer hybrid IDS pipeline.


"""

import os
import json
from pathlib import Path
from typing import List, Dict, Any, Tuple
import logging

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# DIRECTORY PATHS
# ============================================================================

# Base project directory
BASE_DIR: Path = Path(__file__).parent.absolute()

# Data directories
DATA_DIR: Path = BASE_DIR / "data"
RAW_DATA_DIR: Path = DATA_DIR  # CSV files are directly in data directory
PROCESSED_DATA_DIR: Path = DATA_DIR / "processed"

# Model directories
MODELS_DIR: Path = BASE_DIR / "models"
AUTOENCODER_DIR: Path = MODELS_DIR / "autoencoder"
BILSTM_DIR: Path = MODELS_DIR / "bilstm"
META_CLASSIFIER_DIR: Path = MODELS_DIR / "meta_classifier"

# Results and logs
RESULTS_DIR: Path = BASE_DIR / "results"
LOGS_DIR: Path = BASE_DIR / "logs"

# Create all directories if they don't exist
for directory in [DATA_DIR, RAW_DATA_DIR, PROCESSED_DATA_DIR, MODELS_DIR,
                  AUTOENCODER_DIR, BILSTM_DIR, META_CLASSIFIER_DIR,
                  RESULTS_DIR, LOGS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)


# ============================================================================
# FILE PATHS
# ============================================================================

# Input CSV files

OLD_DATASET_CSV = DATA_DIR / "TRAIN_READY_DATASET.csv"  # Your 80k file
NEW_DATASET_CSV = DATA_DIR / "NEW.csv"  # Your 20k file


CLEAN_MASTER_CSV: Path = RAW_DATA_DIR / "TRAIN_READY_DATASET.csv"
FLOW_FEATURES_CSV: Path = RAW_DATA_DIR / "flow_features_clwean2.csv"
PAYLOAD_FEATURES_CSV: Path = RAW_DATA_DIR / "payload_featurees_clean2.csv"

# Metadata file containing CICFlowMeter feature names
META_JSON: Path = RAW_DATA_DIR / "meta.json"

# Processed datasets
META_DATASET_CSV: Path = PROCESSED_DATA_DIR / "meta_dataset.csv"
TRAIN_DATA_PKL: Path = PROCESSED_DATA_DIR / "train_data.pkl"
VAL_DATA_PKL: Path = PROCESSED_DATA_DIR / "val_data.pkl"
TEST_DATA_PKL: Path = PROCESSED_DATA_DIR / "test_data.pkl"

# Layer 1: Signature Filter (no model files needed)

# Layer 2: Autoencoder model files
AE_MODEL_PATH: Path = AUTOENCODER_DIR / "autoencoder.h5"
AE_SCALER_PATH: Path = AUTOENCODER_DIR / "scaler.pkl"
AE_THRESHOLD_PATH: Path = AUTOENCODER_DIR / "ae_threshold.npy"
AE_METADATA_PATH: Path = AUTOENCODER_DIR / "ae_metadata.json"

# Layer 3: Bi-LSTM model files
BILSTM_MODEL_PATH: Path = BILSTM_DIR / "bilstm.h5"
BILSTM_TOKENIZER_PATH: Path = BILSTM_DIR / "tokenizer.pkl"
BILSTM_METADATA_PATH: Path = BILSTM_DIR / "bilstm_metadata.json"

# Meta-Classifier (Random Forest)
RF_MODEL_PATH: Path = META_CLASSIFIER_DIR / "rf_model.pkl"
RF_METADATA_PATH: Path = META_CLASSIFIER_DIR / "rf_metadata.json"

# Results files
EVALUATION_RESULTS: Path = RESULTS_DIR / "evaluation_results.json"
CONFUSION_MATRIX_PATH: Path = RESULTS_DIR / "confusion_matrix.png"
ROC_CURVE_PATH: Path = RESULTS_DIR / "roc_curve.png"


# ============================================================================
# RANDOM SEEDS (for reproducibility)
# ============================================================================

RANDOM_SEED: int = 42
NUMPY_SEED: int = 42
TF_RANDOM_SEED: int = 42
TORCH_SEED: int = 42


# ============================================================================
# DATA SPLIT RATIOS
# ============================================================================

TRAIN_RATIO: float = 0.7
VAL_RATIO: float = 0.15
TEST_RATIO: float = 0.15

assert abs(TRAIN_RATIO + VAL_RATIO + TEST_RATIO - 1.0) < 1e-6, \
    "Train/Val/Test ratios must sum to 1.0"


# ============================================================================
# HTTP FEATURE COLUMNS
# ============================================================================

# HTTP-specific columns from clean_master.csv
HTTP_COLUMNS: List[str] = [
    'src_ip',
    'dst_ip',
    'method',
    'host',
    'uri',
    'user_agent',
    'full_url',
    'referer', 'http_content_type'
]

# Target column
LABEL_COLUMN: str = 'label'  # 0 = benign, 1 = malicious


# ============================================================================
# CICFLOWMETER FLOW FEATURES (82 features)
# ============================================================================

# These will be loaded from meta.json if available
# Default list provided as fallback
DEFAULT_FLOW_FEATURES: List[str] = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
    'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min',
    'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s',
    'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
    'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std',
    'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags',
    'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
    'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
    'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
    'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
    'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
    'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
    'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
    'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk',
    'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk',
    'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes',
    'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
    'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min',
    'SimillarHTTP', 'Inbound'
]


def load_flow_features_from_meta() -> List[str]:
    """
    Load CICFlowMeter feature names from meta.json file.
    
    Returns:
        List[str]: List of 82 flow feature names
    """
    try:
        if META_JSON.exists():
            with open(META_JSON, 'r') as f:
                meta_data: Dict[str, Any] = json.load(f)
                flow_features: List[str] = meta_data.get('flow_features', DEFAULT_FLOW_FEATURES)
                logger.info(f"Loaded {len(flow_features)} flow features from meta.json")
                return flow_features
        else:
            logger.warning(f"meta.json not found at {META_JSON}, using default features")
            return DEFAULT_FLOW_FEATURES
    except Exception as e:
        logger.error(f"Error loading meta.json: {e}. Using default features.")
        return DEFAULT_FLOW_FEATURES


# Load flow features (82 features)
FLOW_FEATURES: List[str] = load_flow_features_from_meta()
NUM_FLOW_FEATURES: int = len(FLOW_FEATURES)


# ==================== LAYER 1: SIGNATURE FILTER ====================

# SQL Injection patterns
SQL_PATTERNS: List[Tuple[str, str]] = [
    ("sql_or_and", r"(\bor\b|\band\b).*=.*"),
    ("sql_union_select", r"union.*select"),
    ("sql_select_from", r"select.*from"),
    ("sql_insert_into", r"insert.*into"),
    ("sql_delete_from", r"delete.*from"),
    ("sql_update_set", r"update.*set"),
    ("sql_drop_table", r"drop.*table"),
    ("sql_exec", r"exec\s*\("),
    ("sql_execute", r"execute\s*\("),
]

# XSS (Cross-Site Scripting) patterns
XSS_PATTERNS: List[Tuple[str, str]] = [
    ("xss_script_tag", r"<script[^>]*>"),
    ("xss_javascript", r"javascript:"),
    ("xss_onerror", r"onerror\s*="),
    ("xss_onload", r"onload\s*="),
    ("xss_onclick", r"onclick\s*="),
    ("xss_iframe", r"<iframe"),
    ("xss_img_onerror", r"<img[^>]+onerror"),
]

# Path Traversal patterns
PATH_TRAVERSAL_PATTERNS: List[Tuple[str, str]] = [
    ("path_traversal_dot_slash", r"\.\.\/"),
    ("path_traversal_dot_dot", r"\.\."),
    ("path_traversal_etc_passwd", r"etc/passwd"),
    ("path_traversal_etc_shadow", r"etc/shadow"),
]

# Command Injection patterns
COMMAND_INJECTION_PATTERNS: List[Tuple[str, str]] = [
    ("cmd_exe", r"cmd\.exe"),
    ("cmd_powershell", r"powershell"),
    ("cmd_bash", r"/bin/bash"),
    ("cmd_sh", r"/bin/sh"),
    ("cmd_netcat", r"nc\s+-e"),
    ("cmd_wget", r"wget\s+http"),
    ("cmd_curl", r"curl\s+http"),
]

# LDAP Injection patterns
LDAP_PATTERNS: List[Tuple[str, str]] = [
    ("ldap_wildcard", r"\*"),
    ("ldap_or_operator", r"\(\|\("),
    ("ldap_and_operator", r"\(&\("),
]

# XML/XXE patterns
XML_PATTERNS: List[Tuple[str, str]] = [
    ("xml_entity", r"<!ENTITY"),
    ("xml_doctype", r"<!DOCTYPE"),
    ("xml_declaration", r"<\?xml"),
]

# Combine all signature patterns
SUSPICIOUS_PATTERNS: List[Tuple[str, str]] = (
    SQL_PATTERNS + XSS_PATTERNS + PATH_TRAVERSAL_PATTERNS + 
    COMMAND_INJECTION_PATTERNS + LDAP_PATTERNS + XML_PATTERNS
)

# Blocklist keywords (simple string matching)
BLOCKLIST: List[str] = [
    "admin", "root", "password", "secret", "token", "key",
    "api_key", "secret_key", "passwd", "pwd", "login",
    "username", "user", "account", "session", "cookie",
    "drop", "delete", "truncate", "alter", "exec",
    "script", "javascript", "eval", "alert", "fetch",
    "curl", "wget", "bash", "sh", "cmd", "powershell",
    "chmod", "chown", "sudo", "su", "whoami", "uname",
    "ifconfig", "ipconfig", "netstat", "ping", "tracert",
    "nmap", "nikto", "sqlmap", "exploit", "payload"
]

# Signature filter configuration
SIGNATURE_FILTER_CONFIG: Dict[str, Any] = {
    'regex_patterns': SUSPICIOUS_PATTERNS,
    'blocklist': BLOCKLIST,
    'case_insensitive': True,
    'use_compiled_patterns': True,
    'pattern_flags': 2,  # re.IGNORECASE
    'confidence_threshold': 0.5,
    'max_pattern_matches': 10,
}

# ============================================================================
# LAYER 2: AUTOENCODER SETTINGS (OPTIMIZED)
# ============================================================================
AE_INPUT_DIM: int = 69           # Corrected dimension
AE_ENCODING_DIM_1: int = 64      # First layer
AE_BOTTLENECK_DIM: int = 16      # Target bottleneck
AE_DECODING_DIM_1: int = 64      # Decoding dim
AE_BATCH_SIZE: int = 2048        # Fast training
AE_EPOCHS: int = 30              # Increased from 15 to learn better
AE_THRESHOLD_PERCENTILE: float = 99.0  # Stricter threshold (was 95)
AE_VALIDATION_SPLIT: float = 0.2
AE_LEARNING_RATE: float = 0.001
AE_EARLY_STOPPING_PATIENCE: int = 10
AE_NOISE_STDDEV: float = 0.1
AE_OUTPUT_DIM: int = NUM_FLOW_FEATURES  # 82

# ============================================================================
# LAYER 3: BI-LSTM SETTINGS (RECALL BOOSTER)
# ============================================================================
BILSTM_CHAR_LEVEL: bool = True
BILSTM_MAX_FEATURES: int = 256
# INCREASED: Catch payloads hidden at the end of long URLs
BILSTM_MAX_SEQUENCE_LENGTH: int = 250 

# Architecture (Safe Upgrade for 4GB VRAM)
BILSTM_EMBEDDING_DIM: int = 32
BILSTM_LSTM_UNITS: int = 96      # Upgraded from 64 (Safe limit)
BILSTM_DENSE_UNITS: int = 64     # Upgraded from 32
BILSTM_DROPOUT_RATE: float = 0.3 # Reduced from 0.5 for faster learning

# Training parameters
BILSTM_BATCH_SIZE: int = 32      # Keep 32 for stability
BILSTM_EPOCHS: int = 1         # Give it time to converge
BILSTM_LEARNING_RATE: float = 0.001
BILSTM_VALIDATION_SPLIT: float = 0.2
BILSTM_EARLY_STOPPING_PATIENCE: int = 3

# SAFETY: Disable Mixed Precision to prevent NaN
USE_MIXED_PRECISION: bool = False




# # ============================================================================
# # LAYER 2: AUTOENCODER HYPERPARAMETERS
# # ============================================================================

# # Architecture
# AE_INPUT_DIM: int = 72   # 77
# AE_ENCODING_DIM_1: int = 64
# AE_BOTTLENECK_DIM: int = 16
# AE_DECODING_DIM_1: int = 64
# AE_OUTPUT_DIM: int = NUM_FLOW_FEATURES  # 82

# # Noise injection for denoising autoencoder
# AE_NOISE_STDDEV: float = 0.1

# # Training parameters
# AE_BATCH_SIZE: int = 2048
# AE_EPOCHS: int = 15
# AE_LEARNING_RATE: float = 0.001
# AE_VALIDATION_SPLIT: float = 0.2
# AE_EARLY_STOPPING_PATIENCE: int = 10

# # Anomaly threshold percentile (95th or 99th)
# AE_THRESHOLD_PERCENTILE: float = 99.0  # Can be adjusted to 99.0 for stricter filtering


# # # ============================================================================
# # # LAYER 3: BI-LSTM HYPERPARAMETERS
# # # ============================================================================

# # ============================================================================
# # LAYER 3: BI-LSTM HYPERPARAMETERS - QUICK TEST MODE
# # ============================================================================

# # Tokenizer configuration
# BILSTM_CHAR_LEVEL: bool = True  # Character-level tokenization
# BILSTM_MAX_FEATURES: int = 128  # REDUCED: 256 → 128 (fewer characters)
# BILSTM_MAX_SEQUENCE_LENGTH: int = 200  # REDUCED: 200 → 100 (shorter sequences)

# # Architecture - SIMPLIFIED
# BILSTM_EMBEDDING_DIM: int = 32  # REDUCED: 32 → 16
# BILSTM_LSTM_UNITS: int = 64  # REDUCED: 64 → 32
# BILSTM_DENSE_UNITS: int = 32  # REDUCED: 64 → 32
# BILSTM_DROPOUT_RATE: float = 0.4  # INCREASED: 0.2 → 0.3 (faster convergence)

# # Training parameters - FAST MODE
# BILSTM_BATCH_SIZE: int = 32  # INCREASED: 64 → 128 (fewer iterations)
# BILSTM_EPOCHS: int = 7
# BILSTM_LEARNING_RATE: float = 0.001  # INCREASED: 0.001 → 0.01 (faster learning)
# BILSTM_VALIDATION_SPLIT: float = 0.2
# BILSTM_EARLY_STOPPING_PATIENCE: int = 2  # REDUCED: 5 → 2 (stop early)

# USE_MIXED_PRECISION: bool = False
# ============================================================================
# META-CLASSIFIER (RANDOM FOREST) HYPERPARAMETERS
# ============================================================================

# Meta-features from the three layers
META_FEATURES: List[str] = [
    'layer1_flag',      # Binary: 0 or 1 from signature filter
    'ae_error',         # Float: reconstruction error from autoencoder
    'ae_flag',          # Binary: 0 or 1 based on threshold
    'bilstm_confidence' # Float: [0, 1] confidence from Bi-LSTM
]

# Random Forest configuration
RF_N_ESTIMATORS: int = 100
RF_MAX_DEPTH: int = 10
RF_MIN_SAMPLES_SPLIT: int = 5
RF_MIN_SAMPLES_LEAF: int = 2
RF_MAX_FEATURES: str = 'sqrt'  # 'sqrt', 'log2', or int
RF_RANDOM_STATE: int = RANDOM_SEED
RF_N_JOBS: int = -1  # Use all CPU cores

# Optional: XGBoost configuration (if using XGBoost instead of/alongside RF)
XGB_N_ESTIMATORS: int = 100
XGB_MAX_DEPTH: int = 6
XGB_LEARNING_RATE: float = 0.1
XGB_SUBSAMPLE: float = 0.8
XGB_COLSAMPLE_BYTREE: float = 0.8
XGB_RANDOM_STATE: int = RANDOM_SEED


# ============================================================================
# PAYLOAD NORMALIZATION CONFIGURATION
# ============================================================================

# URL decoding iterations
URL_DECODE_ITERATIONS: int = 3

# Unicode normalization form ('NFC', 'NFKC', 'NFD', 'NFKD')
UNICODE_NORMALIZATION: str = 'NFKC'

# Convert to lowercase
NORMALIZE_LOWERCASE: bool = True

# Remove null bytes and control characters
REMOVE_CONTROL_CHARS: bool = True


# ============================================================================
# EVALUATION METRICS
# ============================================================================

METRICS_TO_COMPUTE: List[str] = [
    'accuracy',
    'precision',
    'recall',
    'f1_score',
    'roc_auc',
    'confusion_matrix'
]


# ============================================================================
# INFERENCE CONFIGURATION
# ============================================================================

# Batch size for cascade prediction
INFERENCE_BATCH_SIZE: int = 1

# Confidence threshold for final decision
CONFIDENCE_THRESHOLD: float = 0.5


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_config_summary() -> Dict[str, Any]:
    """
    Get a summary of all configuration parameters.
    
    Returns:
        Dict[str, Any]: Configuration summary dictionary
    """
    summary: Dict[str, Any] = {
        'directories': {
            'base_dir': str(BASE_DIR),
            'data_dir': str(DATA_DIR),
            'models_dir': str(MODELS_DIR),
            'results_dir': str(RESULTS_DIR)
        },
        'data': {
            'train_ratio': TRAIN_RATIO,
            'val_ratio': VAL_RATIO,
            'test_ratio': TEST_RATIO,
            'num_flow_features': NUM_FLOW_FEATURES
        },
        'layer1': {
            'blocklist_size': len(BLOCKLIST),
            'patterns_count': len(SUSPICIOUS_PATTERNS)
        },
        'layer2_autoencoder': {
            'input_dim': AE_INPUT_DIM,
            'bottleneck_dim': AE_BOTTLENECK_DIM,
            'batch_size': AE_BATCH_SIZE,
            'epochs': AE_EPOCHS,
            'threshold_percentile': AE_THRESHOLD_PERCENTILE
        },
        'layer3_bilstm': {
            'char_level': BILSTM_CHAR_LEVEL,
            'max_sequence_length': BILSTM_MAX_SEQUENCE_LENGTH,
            'lstm_units': BILSTM_LSTM_UNITS,
            'batch_size': BILSTM_BATCH_SIZE,
            'epochs': BILSTM_EPOCHS
        },
        'meta_classifier': {
            'algorithm': 'RandomForest',
            'n_estimators': RF_N_ESTIMATORS,
            'max_depth': RF_MAX_DEPTH,
            'meta_features': META_FEATURES
        },
        'random_seed': RANDOM_SEED
    }
    return summary


def save_config_summary(output_path: Path = RESULTS_DIR / "config_summary.json") -> None:
    """
    Save configuration summary to JSON file.
    
    Args:
        output_path: Path to save the configuration summary
    """
    summary: Dict[str, Any] = get_config_summary()
    try:
        with open(output_path, 'w') as f:
            json.dump(summary, f, indent=4)
        logger.info(f"Configuration summary saved to {output_path}")
    except Exception as e:
        logger.error(f"Failed to save configuration summary: {e}")


if __name__ == "__main__":
    # Display configuration summary
    summary = get_config_summary()
    print("\n" + "="*80)
    print("HYBRID IDS CONFIGURATION SUMMARY")
    print("="*80)
    print(json.dumps(summary, indent=2))
    print("="*80 + "\n")
    
    # Save configuration
    save_config_summary()