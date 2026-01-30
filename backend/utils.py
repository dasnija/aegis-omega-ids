"""
Utility Functions & Helpers for Hybrid Intrusion Detection System (IDS)

This module provides reusable utility functions for:
- Logging configuration and helpers
- Data preprocessing utilities
- Visualization helpers
- Metric calculation functions
- File I/O utilities
- Performance profiling
- Model management

Author: Senior ML Engineer
Date: 2025
"""

import logging
import pickle
import json
import time
import psutil
import os
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable, Tuple
from functools import wraps
from contextlib import contextmanager
from datetime import datetime
import numpy as np
import pandas as pd

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score
)


# ==================== LOGGING UTILITIES ====================

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for terminal output"""
    
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[41m',   # Red background
        'RESET': '\033[0m'
    }
    
    def format(self, record):
        """Format log record with colors"""
        if record.levelname in self.COLORS:
            color = self.COLORS[record.levelname]
            reset = self.COLORS['RESET']
            record.levelname = f"{color}{record.levelname}{reset}"
        
        return super().format(record)


def setup_logger(name: str,
                log_file: Optional[Path] = None,
                level: int = logging.INFO,
                use_color: bool = True) -> logging.Logger:
    """
    Setup and configure a logger
    
    Args:
        name: Logger name
        log_file: Optional file path for logging
        level: Logging level
        use_color: Use colored output in console
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    
    if use_color:
        formatter = ColoredFormatter(
            '[%(asctime)s] - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    else:
        formatter = logging.Formatter(
            '[%(asctime)s] - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (optional)
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_formatter = logging.Formatter(
            '[%(asctime)s] - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger


# ==================== PERFORMANCE PROFILING ====================

def time_operation(operation_name: str):
    """Decorator to time function execution"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger = logging.getLogger(__name__)
            start_time = time.time()
            logger.info(f"Starting: {operation_name}")
            
            try:
                result = func(*args, **kwargs)
                elapsed = time.time() - start_time
                logger.info(f"✓ {operation_name} completed in {elapsed:.2f}s")
                return result
            except Exception as e:
                elapsed = time.time() - start_time
                logger.error(f"{operation_name} failed after {elapsed:.2f}s: {str(e)}")
                raise
        
        return wrapper
    return decorator


@contextmanager
def timer(operation_name: str, verbose: bool = True):
    """Context manager for timing code blocks"""
    start_time = time.time()
    if verbose:
        print(f"⏱️  Starting: {operation_name}")
    
    try:
        yield
    finally:
        elapsed = time.time() - start_time
        if verbose:
            print(f"✓ {operation_name} completed in {elapsed:.2f}s")


def get_memory_usage() -> Dict[str, float]:
    """Get current memory usage"""
    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    
    return {
        'rss_mb': mem_info.rss / 1024 / 1024,  # Resident Set Size
        'vms_mb': mem_info.vms / 1024 / 1024,  # Virtual Memory Size
        'percent': process.memory_percent()
    }


def profile_memory(func: Callable) -> Callable:
    """Decorator to profile memory usage"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        mem_before = get_memory_usage()
        result = func(*args, **kwargs)
        mem_after = get_memory_usage()
        
        delta = {
            'rss_mb': mem_after['rss_mb'] - mem_before['rss_mb'],
            'vms_mb': mem_after['vms_mb'] - mem_before['vms_mb']
        }
        
        logger = logging.getLogger(__name__)
        logger.info(f"Memory change: RSS={delta['rss_mb']:+.2f}MB, VMS={delta['vms_mb']:+.2f}MB")
        
        return result
    
    return wrapper


# ==================== DATA PREPROCESSING ====================

def normalize_text(text: str) -> str:
    """Normalize text for preprocessing"""
    text = text.lower()
    text = ''.join(c for c in text if 32 <= ord(c) <= 126)
    return text


def remove_outliers(data: np.ndarray, method: str = 'iqr', threshold: float = 1.5) -> np.ndarray:
    """
    Remove outliers from data
    
    Args:
        data: Input array
        method: 'iqr' or 'zscore'
        threshold: Outlier threshold
        
    Returns:
        Cleaned data
    """
    if method == 'iqr':
        Q1 = np.percentile(data, 25)
        Q3 = np.percentile(data, 75)
        IQR = Q3 - Q1
        lower = Q1 - threshold * IQR
        upper = Q3 + threshold * IQR
        return data[(data >= lower) & (data <= upper)]
    
    elif method == 'zscore':
        z_scores = np.abs((data - np.mean(data)) / np.std(data))
        return data[z_scores < threshold]
    
    return data


def balance_dataset(X: np.ndarray,
                   y: np.ndarray,
                   method: str = 'oversample') -> Tuple[np.ndarray, np.ndarray]:
    """
    Balance imbalanced dataset
    
    Args:
        X: Features
        y: Labels
        method: 'oversample' or 'undersample'
        
    Returns:
        Balanced X, y
    """
    unique, counts = np.unique(y, return_counts=True)
    
    if method == 'oversample':
        max_count = np.max(counts)
        indices = np.arange(len(y))
        
        balanced_indices = list(indices[y == unique[0]])
        for label in unique[1:]:
            label_indices = indices[y == label]
            if len(label_indices) < max_count:
                balanced_indices.extend(
                    np.random.choice(label_indices, size=max_count - len(label_indices), replace=True)
                )
            else:
                balanced_indices.extend(label_indices)
        
        balanced_indices = np.array(balanced_indices)
        return X[balanced_indices], y[balanced_indices]
    
    elif method == 'undersample':
        min_count = np.min(counts)
        balanced_indices = []
        
        for label in unique:
            label_indices = indices[y == label]
            balanced_indices.extend(
                np.random.choice(label_indices, size=min_count, replace=False)
            )
        
        balanced_indices = np.array(balanced_indices)
        return X[balanced_indices], y[balanced_indices]
    
    return X, y


def create_train_val_test_split(X: np.ndarray,
                               y: np.ndarray,
                               train_ratio: float = 0.7,
                               val_ratio: float = 0.15,
                               test_ratio: float = 0.15,
                               random_state: int = 42) -> Dict[str, Tuple[np.ndarray, np.ndarray]]:
    """
    Create train/val/test split maintaining class balance
    
    Args:
        X: Features
        y: Labels
        train_ratio: Training set ratio
        val_ratio: Validation set ratio
        test_ratio: Test set ratio
        random_state: Random seed
        
    Returns:
        Dictionary with splits
    """
    from sklearn.model_selection import train_test_split
    
    np.random.seed(random_state)
    
    # First split: train + temp
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y,
        test_size=1 - train_ratio,
        stratify=y,
        random_state=random_state
    )
    
    # Second split: val + test
    val_size = val_ratio / (val_ratio + test_ratio)
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp,
        test_size=1 - val_size,
        stratify=y_temp,
        random_state=random_state
    )
    
    return {
        'train': (X_train, y_train),
        'val': (X_val, y_val),
        'test': (X_test, y_test)
    }


# ==================== METRIC CALCULATION ====================

def calculate_all_metrics(y_true: np.ndarray,
                         y_pred: np.ndarray,
                         y_proba: Optional[np.ndarray] = None) -> Dict[str, float]:
    """
    Calculate comprehensive set of metrics
    
    Args:
        y_true: True labels
        y_pred: Predicted labels
        y_proba: Predicted probabilities (optional)
        
    Returns:
        Dictionary with all metrics
    """
    metrics = {
        'accuracy': float(accuracy_score(y_true, y_pred)),
        'precision': float(precision_score(y_true, y_pred, zero_division=0)),
        'recall': float(recall_score(y_true, y_pred, zero_division=0)),
        'f1': float(f1_score(y_true, y_pred, zero_division=0))
    }
    
    if y_proba is not None and len(np.unique(y_true)) > 1:
        metrics['roc_auc'] = float(roc_auc_score(y_true, y_proba))
    
    cm = confusion_matrix(y_true, y_pred)
    if cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
        metrics['specificity'] = float(tn / (tn + fp)) if (tn + fp) > 0 else 0.0
        metrics['sensitivity'] = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        metrics['fpr'] = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        metrics['fnr'] = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    
    return metrics


def format_metrics(metrics: Dict[str, float], decimals: int = 4) -> Dict[str, str]:
    """Format metrics for display"""
    return {k: f"{v:.{decimals}f}" for k, v in metrics.items()}


# ==================== FILE I/O UTILITIES ====================

def save_model(model: Any, filepath: Path) -> None:
    """Save model to disk"""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'wb') as f:
        pickle.dump(model, f)
    logging.getLogger(__name__).info(f"✓ Model saved to {filepath}")


def load_model(filepath: Path) -> Any:
    """Load model from disk"""
    with open(filepath, 'rb') as f:
        model = pickle.load(f)
    logging.getLogger(__name__).info(f"✓ Model loaded from {filepath}")
    return model


def save_json(data: Dict[str, Any], filepath: Path) -> None:
    """Save data to JSON file"""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)
    logging.getLogger(__name__).info(f"✓ Data saved to {filepath}")


def load_json(filepath: Path) -> Dict[str, Any]:
    """Load data from JSON file"""
    with open(filepath, 'r') as f:
        data = json.load(f)
    logging.getLogger(__name__).info(f"✓ Data loaded from {filepath}")
    return data


def save_csv(data: pd.DataFrame, filepath: Path) -> None:
    """Save DataFrame to CSV"""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    data.to_csv(filepath, index=False)
    logging.getLogger(__name__).info(f"✓ CSV saved to {filepath}")


def load_csv(filepath: Path) -> pd.DataFrame:
    """Load DataFrame from CSV"""
    data = pd.read_csv(filepath)
    logging.getLogger(__name__).info(f"✓ CSV loaded from {filepath}")
    return data


# ==================== VISUALIZATION UTILITIES ====================

def plot_metrics_comparison(metrics_dict: Dict[str, Dict[str, float]],
                           title: str = "Metrics Comparison",
                           figsize: Tuple[int, int] = (12, 6)) -> Path:
    """
    Plot metrics comparison across multiple models/layers
    
    Args:
        metrics_dict: {name: {metric: value}}
        title: Plot title
        figsize: Figure size
        
    Returns:
        Path to saved figure
    """
    df = pd.DataFrame(metrics_dict).T
    
    fig, ax = plt.subplots(figsize=figsize)
    df.plot(kind='bar', ax=ax, width=0.8)
    
    ax.set_title(title, fontsize=14, fontweight='bold')
    ax.set_ylabel('Score', fontsize=12)
    ax.set_xlabel('Model/Layer', fontsize=12)
    ax.legend(loc='best')
    ax.set_ylim([0, 1.1])
    ax.grid(axis='y', alpha=0.3)
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    path = Path(f"metrics_comparison_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png")
    plt.savefig(path, dpi=300, bbox_inches='tight')
    plt.close()
    
    return path


def plot_confusion_matrices(cm_dict: Dict[str, np.ndarray],
                            figsize: Tuple[int, int] = (14, 6)) -> Path:
    """
    Plot multiple confusion matrices
    
    Args:
        cm_dict: {name: confusion_matrix}
        figsize: Figure size
        
    Returns:
        Path to saved figure
    """
    n_plots = len(cm_dict)
    fig, axes = plt.subplots(1, n_plots, figsize=figsize)
    
    if n_plots == 1:
        axes = [axes]
    
    for ax, (name, cm) in zip(axes, cm_dict.items()):
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax, cbar=False)
        ax.set_title(name, fontweight='bold')
        ax.set_ylabel('True Label')
        ax.set_xlabel('Predicted Label')
    
    plt.tight_layout()
    path = Path(f"confusion_matrices_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png")
    plt.savefig(path, dpi=300, bbox_inches='tight')
    plt.close()
    
    return path


def plot_learning_curve(train_scores: List[float],
                       val_scores: List[float],
                       title: str = "Learning Curve",
                       figsize: Tuple[int, int] = (10, 6)) -> Path:
    """
    Plot learning curves
    
    Args:
        train_scores: Training scores per epoch
        val_scores: Validation scores per epoch
        title: Plot title
        figsize: Figure size
        
    Returns:
        Path to saved figure
    """
    fig, ax = plt.subplots(figsize=figsize)
    
    epochs = np.arange(1, len(train_scores) + 1)
    ax.plot(epochs, train_scores, 'o-', label='Train', linewidth=2, markersize=4)
    ax.plot(epochs, val_scores, 's-', label='Validation', linewidth=2, markersize=4)
    
    ax.set_title(title, fontsize=14, fontweight='bold')
    ax.set_xlabel('Epoch', fontsize=12)
    ax.set_ylabel('Score', fontsize=12)
    ax.legend(fontsize=11)
    ax.grid(alpha=0.3)
    
    plt.tight_layout()
    path = Path(f"learning_curve_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png")
    plt.savefig(path, dpi=300, bbox_inches='tight')
    plt.close()
    
    return path


# ==================== MODEL MANAGEMENT ====================

def get_model_info(model_path: Path) -> Dict[str, Any]:
    """Get information about a saved model"""
    if not model_path.exists():
        return {'status': 'not_found'}
    
    stat = model_path.stat()
    return {
        'path': str(model_path),
        'size_mb': stat.st_size / 1024 / 1024,
        'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
    }


def list_models(models_dir: Path) -> Dict[str, Dict[str, Any]]:
    """List all models in a directory"""
    models = {}
    
    if not models_dir.exists():
        return models
    
    for model_file in models_dir.glob('*.pkl'):
        models[model_file.name] = get_model_info(model_file)
    
    for model_file in models_dir.glob('*.h5'):
        models[model_file.name] = get_model_info(model_file)
    
    return models


def cleanup_old_models(models_dir: Path, keep_recent: int = 5) -> int:
    """Keep only the most recent N models"""
    model_files = sorted(
        models_dir.glob('*.pkl') + models_dir.glob('*.h5'),
        key=lambda x: x.stat().st_mtime,
        reverse=True
    )
    
    deleted_count = 0
    for model_file in model_files[keep_recent:]:
        model_file.unlink()
        deleted_count += 1
        logging.getLogger(__name__).info(f"Deleted old model: {model_file.name}")
    
    return deleted_count


# ==================== CONFIGURATION MANAGEMENT ====================

def save_config(config: Dict[str, Any], filepath: Path) -> None:
    """Save configuration to JSON"""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'w') as f:
        json.dump(config, f, indent=2)
    logging.getLogger(__name__).info(f"✓ Config saved to {filepath}")


def load_config(filepath: Path) -> Dict[str, Any]:
    """Load configuration from JSON"""
    with open(filepath, 'r') as f:
        config = json.load(f)
    logging.getLogger(__name__).info(f"✓ Config loaded from {filepath}")
    return config


def merge_configs(base_config: Dict[str, Any],
                 override_config: Dict[str, Any]) -> Dict[str, Any]:
    """Merge two configurations (override takes precedence)"""
    merged = base_config.copy()
    merged.update(override_config)
    return merged


# ==================== REPORTING UTILITIES ====================

def generate_summary_report(evaluation_results: Dict[str, Any]) -> str:
    """Generate text summary report from evaluation results"""
    report = "\n" + "=" * 80 + "\n"
    report += "HYBRID IDS - EVALUATION SUMMARY REPORT\n"
    report += "=" * 80 + "\n\n"
    
    if 'overall_metrics' in evaluation_results:
        metrics = evaluation_results['overall_metrics']
        report += "OVERALL METRICS:\n"
        report += "-" * 80 + "\n"
        for key, value in metrics.items():
            if isinstance(value, float):
                report += f"  {key:.<40} {value:.4f}\n"
            else:
                report += f"  {key:.<40} {value}\n"
        report += "\n"
    
    if 'error_analysis' in evaluation_results:
        errors = evaluation_results['error_analysis']
        report += "ERROR ANALYSIS:\n"
        report += "-" * 80 + "\n"
        report += f"  False Positives: {errors['false_positives']['count']} ({errors['false_positives']['percentage']:.2f}%)\n"
        report += f"  False Negatives: {errors['false_negatives']['count']} ({errors['false_negatives']['percentage']:.2f}%)\n"
        report += f"  Total Errors: {errors['total_errors']} ({errors['error_rate']:.2f}% error rate)\n"
        report += "\n"
    
    report += "=" * 80 + "\n"
    return report


def save_summary_report(evaluation_results: Dict[str, Any], filepath: Path) -> None:
    """Save summary report to text file"""
    report = generate_summary_report(evaluation_results)
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, 'w') as f:
        f.write(report)
    logging.getLogger(__name__).info(f"✓ Summary report saved to {filepath}")


# ==================== MAIN ====================

if __name__ == "__main__":
    # Example usage
    logger = setup_logger("utils", use_color=True)
    
    logger.info("Utility functions loaded successfully")
    logger.info(f"Memory usage: {get_memory_usage()}")