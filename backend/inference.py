"""
Enhanced Inference Pipeline with Attack Success Detection and Comprehensive Evaluation Metrics

This module includes:
1. All 4 layers of IDS (Signature, Autoencoder, BiLSTM, Meta-Classifier)
2. Attack Success Analyzer - determines if attack was successful
3. Attack Classification (type, subtype, severity)
4. Network Evidence extraction
5. Detailed JSON output with evaluation metrics
6. Comprehensive performance metrics: Accuracy, Precision, Recall, F1, Confusion Matrix, ROC-AUC
7. **FIXED**: HTTPS payload handling and confusion matrix edge cases

Author: Senior ML Engineer
Date: 2025
"""

import logging
import pickle
import json
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
import numpy as np
import pandas as pd
from tqdm import tqdm
import tensorflow as tf
from tensorflow import keras
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score, roc_curve
)
import matplotlib.pyplot as plt
import seaborn as sns

# Import your modules
import config
from signature_filter import SignatureFilter
from autoencoder import AdvancedAutoencoder
from bilstm_classifier import AdvancedBiLSTM
from meta_classifier import MetaClassifier

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AttackSuccessAnalyzer:
    """
    Analyzes network flow features to determine if an attack was successful.
    """
    
    # Attack type to severity mapping
    ATTACK_SEVERITY = {
        'sql_injection': 9,
        'xss': 7,
        'ssrf': 8,
        'lfi': 9,
        'rfi': 9,
        'directory_traversal': 8,
        'command_injection': 10,
        'credential_stuffing': 7,
        'brute_force': 6,
        'http_param_pollution': 6,
        'xxe': 9,
        'webshell': 10,
        'typosquatting': 5
    }
    
    def __init__(self):
        """Initialize the analyzer with success detection rules."""
        self.success_indicators = {
            'http_200': {'weight': 0.4, 'description': 'HTTP 200 OK received'},
            'http_redirect': {'weight': 0.2, 'description': 'Redirect received'},
            'high_backward_packets': {'weight': 0.3, 'description': 'High response data'},
            'normal_termination': {'weight': 0.15, 'description': 'Normal FIN termination'},
            'no_rst_flag': {'weight': 0.15, 'description': 'No RST flag'},
        }
    
    def analyze_attack_success(self, 
                               row: pd.Series,
                               attack_type: str,
                               is_malicious: bool) -> Dict[str, Any]:
        """
        Determine if an attack was successful based on network evidence.
        """
        
        if not is_malicious:
            return {
                'attack_detected': False,
                'attack_outcome': 'BENIGN',
                'success_confidence': 0.0,
                'reasoning': ['No attack detected']
            }
        
        # Extract network features
        success_score = 0.0
        reasoning = []
        
        # Check HTTP status codes
        http_status = row.get('http_status', None)
        if pd.notna(http_status):
            status = int(http_status)
            
            if status == 200:
                success_score += 0.4
                reasoning.append('HTTP 200 OK received')
            elif status in [301, 302, 303, 307, 308]:
                success_score += 0.2
                reasoning.append(f'HTTP {status} redirect received')
            elif status >= 400:
                success_score -= 0.3
                reasoning.append(f'HTTP {status} error - likely failed')
        
        # Check backward packets (response size)
        tot_bwd_pkts = row.get('tot_bwd_pkts', 0)
        totlen_bwd_pkts = row.get('totlen_bwd_pkts', 0)
        
        if tot_bwd_pkts > 5:
            success_score += 0.3
            reasoning.append('High backward packet count')
        
        if totlen_bwd_pkts > 1000:
            success_score += 0.2
            reasoning.append('Large response size - server sent data')
        
        # Check connection termination
        fin_flag_cnt = row.get('fin_flag_cnt', 0)
        rst_flag_cnt = row.get('rst_flag_cnt', 0)
        
        if fin_flag_cnt > 0 and rst_flag_cnt == 0:
            success_score += 0.15
            reasoning.append('Normal FIN termination')
        
        if rst_flag_cnt == 0:
            success_score += 0.15
            reasoning.append('No RST observed')
        else:
            success_score -= 0.2
            reasoning.append('RST flag detected - connection aborted')
        
        # Check flow duration
        flow_duration = row.get('flow_duration', 0)
        if flow_duration > 1.0:
            success_score += 0.1
            reasoning.append('Long flow duration - sustained connection')
        
        # Attack-specific heuristics
        if attack_type == 'sql_injection' and totlen_bwd_pkts > 5000:
            success_score += 0.3
            reasoning.append('Large SQL response - data exfiltration likely')
        elif attack_type == 'xss' and http_status == 200:
            success_score += 0.2
            reasoning.append('XSS payload delivered successfully')
        elif attack_type in ['lfi', 'rfi', 'directory_traversal'] and totlen_bwd_pkts > 2000:
            success_score += 0.4
            reasoning.append('Large file content returned')
        elif attack_type == 'ssrf' and http_status == 200 and totlen_bwd_pkts > 500:
            success_score += 0.4
            reasoning.append('SSRF likely accessed internal resource')
        elif attack_type == 'command_injection' and flow_duration > 2.0:
            success_score += 0.3
            reasoning.append('Long execution time - command likely executed')
        elif attack_type in ['credential_stuffing', 'brute_force'] and http_status in [200, 301, 302]:
            success_score += 0.4
            reasoning.append('Authentication likely successful')
        elif attack_type == 'webshell' and http_status == 200 and row.get('method', '') == 'POST':
            success_score += 0.5
            reasoning.append('POST with 200 OK - upload likely successful')
        
        # Normalize score
        success_confidence = min(max(success_score, 0.0), 1.0)
        
        # Determine outcome
        if success_confidence >= 0.7:
            attack_outcome = 'SUCCESSFUL_ATTACK'
        elif success_confidence >= 0.4:
            attack_outcome = 'LIKELY_SUCCESSFUL'
        elif success_confidence >= 0.2:
            attack_outcome = 'PARTIALLY_SUCCESSFUL'
        else:
            attack_outcome = 'FAILED_ATTACK'
        
        return {
            'attack_detected': True,
            'attack_outcome': attack_outcome,
            'success_confidence': round(success_confidence, 4),
            'reasoning': reasoning if reasoning else ['Insufficient evidence']
        }
    
    def classify_attack(self, matched_patterns: List[str]) -> Dict[str, Any]:
        """
        Classify attack type, subtype, and severity from matched patterns.
        """
        if not matched_patterns:
            return {
                'attack_type': 'unknown',
                'subtype': 'unclassified',
                'severity': 0
            }
        
        # Parse first pattern
        first_pattern = matched_patterns[0].split(':', 1)[-1] if matched_patterns else ''
        
        # Map patterns to attack types
        attack_mapping = {
            'sqli': ('sql_injection', 'generic_sqli'),
            'union': ('sql_injection', 'union_based'),
            'blind': ('sql_injection', 'blind_sqli'),
            'error': ('sql_injection', 'error_based'),
            'xss': ('xss', 'reflected_xss'),
            'script': ('xss', 'stored_xss'),
            'onerror': ('xss', 'event_handler'),
            'ssrf': ('ssrf', 'internal_access'),
            'metadata': ('ssrf', 'internal_metadata_access'),
            'lfi': ('lfi', 'local_traversal'),
            'rfi': ('rfi', 'remote_inclusion'),
            'traversal': ('directory_traversal', 'path_traversal'),
            'dotdot': ('directory_traversal', 'parent_directory'),
            'cmd': ('command_injection', 'shell_command'),
            'exec': ('command_injection', 'code_execution'),
            'webshell': ('webshell', 'shell_upload'),
            'backdoor': ('webshell', 'backdoor_upload'),
            'admin': ('credential_stuffing', 'admin_access'),
            'login': ('brute_force', 'login_attempt'),
            'xxe': ('xxe', 'entity_injection'),
            'param': ('http_param_pollution', 'parameter_manipulation')
        }
        
        # Find matching attack type
        attack_type = 'unknown'
        subtype = 'unclassified'
        
        pattern_lower = first_pattern.lower()
        for key, (atype, asub) in attack_mapping.items():
            if key in pattern_lower:
                attack_type = atype
                subtype = asub
                break
        
        # Get severity
        severity = self.ATTACK_SEVERITY.get(attack_type, 5)
        
        return {
            'attack_type': attack_type,
            'subtype': subtype,
            'severity': severity
        }


class EvaluationMetrics:
    """
    Comprehensive evaluation metrics calculator and visualizer.
    """
    
    @staticmethod
    def calculate_all_metrics(y_true: np.ndarray, 
                             y_pred: np.ndarray, 
                             y_proba: np.ndarray = None) -> Dict[str, Any]:
        """
        Calculate comprehensive evaluation metrics.
        Handles both binary and multi-class classification.
        """
        metrics = {}
        
        # Detect if binary or multi-class
        unique_classes = np.unique(np.concatenate([y_true, y_pred]))
        is_binary = len(unique_classes) <= 2
        
        # Set average parameter based on classification type
        avg_param = 'binary' if is_binary else 'weighted'
        
        # Basic metrics
        metrics['accuracy'] = accuracy_score(y_true, y_pred)
        metrics['precision'] = precision_score(y_true, y_pred, average=avg_param, zero_division=0)
        metrics['recall'] = recall_score(y_true, y_pred, average=avg_param, zero_division=0)
        metrics['f1_score'] = f1_score(y_true, y_pred, average=avg_param, zero_division=0)
        
        # Confusion matrix with labels to ensure 2x2 matrix for binary
        if is_binary:
            cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        else:
            cm = confusion_matrix(y_true, y_pred)
        metrics['confusion_matrix'] = cm.tolist()
        
        # Detailed confusion matrix breakdown - handle edge cases
        # For multi-class, we skip binary-specific metrics
        if is_binary:
            if cm.shape == (2, 2):
                tn, fp, fn, tp = cm.ravel()
            elif cm.shape == (1, 1):
                # All predictions are same class
                if y_pred[0] == 0:  # All predicted benign
                    tn, fp, fn, tp = int(cm[0, 0]), 0, 0, 0
                else:  # All predicted malicious
                    tn, fp, fn, tp = 0, 0, 0, int(cm[0, 0])
            else:
                tn, fp, fn, tp = 0, 0, 0, 0
                
            metrics['true_negatives'] = int(tn)
            metrics['false_positives'] = int(fp)
            metrics['false_negatives'] = int(fn)
            metrics['true_positives'] = int(tp)
            
            # False positive/negative rates
            metrics['false_positive_rate'] = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
            metrics['false_negative_rate'] = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
            
            # Specificity and sensitivity
            metrics['specificity'] = float(tn / (tn + fp)) if (tn + fp) > 0 else 0.0
            metrics['sensitivity'] = metrics['recall']  # Same as recall
        else:
            # For multi-class, provide per-class metrics
            metrics['is_multiclass'] = True
            metrics['num_classes'] = len(unique_classes)
            metrics['specificity'] = None
            metrics['sensitivity'] = metrics['recall']
        
        # ROC-AUC if probabilities provided
        if y_proba is not None:
            try:
                # Check if we have both classes for ROC-AUC
                if len(np.unique(y_true)) > 1:
                    if is_binary:
                        metrics['roc_auc'] = roc_auc_score(y_true, y_proba)
                    else:
                        # For multi-class, use one-vs-rest
                        metrics['roc_auc'] = roc_auc_score(y_true, y_proba, multi_class='ovr', average='weighted')
                else:
                    metrics['roc_auc'] = None
            except:
                metrics['roc_auc'] = None
        
        # Classification report - handle multi-class
        try:
            if is_binary:
                report = classification_report(y_true, y_pred, 
                                              labels=[0, 1],
                                              target_names=['Benign', 'Malicious'],
                                              output_dict=True, zero_division=0)
            else:
                report = classification_report(y_true, y_pred, 
                                              output_dict=True, zero_division=0)
            metrics['classification_report'] = report
        except Exception as e:
            logger.warning(f"Could not generate full classification report: {e}")
            metrics['classification_report'] = None
        
        return metrics
    
    @staticmethod
    def print_metrics(metrics: Dict[str, Any], title: str = "Evaluation Metrics"):
        """
        Pretty print evaluation metrics.
        """
        logger.info("\n" + "=" * 80)
        logger.info(f"{title:^80}")
        logger.info("=" * 80)
        
        # Overall metrics
        logger.info("\n📊 Overall Performance:")
        logger.info(f"   Accuracy:  {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
        logger.info(f"   Precision: {metrics['precision']:.4f} ({metrics['precision']*100:.2f}%)")
        logger.info(f"   Recall:    {metrics['recall']:.4f} ({metrics['recall']*100:.2f}%)")
        logger.info(f"   F1-Score:  {metrics['f1_score']:.4f} ({metrics['f1_score']*100:.2f}%)")
        
        if metrics.get('roc_auc') is not None:
            logger.info(f"   ROC-AUC:   {metrics['roc_auc']:.4f}")
        
        # Check if binary or multi-class
        is_multiclass = metrics.get('is_multiclass', False)
        
        if not is_multiclass and 'true_negatives' in metrics:
            # Confusion matrix for binary classification
            logger.info("\n📈 Confusion Matrix:")
            logger.info("                Predicted")
            logger.info("              Benign  Malicious")
            logger.info(f"   Actual Benign    {metrics['true_negatives']:6d}  {metrics['false_positives']:6d}")
            logger.info(f"        Malicious   {metrics['false_negatives']:6d}  {metrics['true_positives']:6d}")
            
            # Detailed breakdown
            logger.info("\n🔍 Detailed Breakdown:")
            logger.info(f"   True Positives:     {metrics['true_positives']:6d}  (Correctly detected attacks)")
            logger.info(f"   True Negatives:     {metrics['true_negatives']:6d}  (Correctly identified benign)")
            logger.info(f"   False Positives:    {metrics['false_positives']:6d}  (Benign flagged as attack)")
            logger.info(f"   False Negatives:    {metrics['false_negatives']:6d}  (Missed attacks)")
            
            # Error rates
            logger.info("\n⚠️ Error Rates:")
            logger.info(f"   False Positive Rate: {metrics['false_positive_rate']:.4f} ({metrics['false_positive_rate']*100:.2f}%)")
            logger.info(f"   False Negative Rate: {metrics['false_negative_rate']:.4f} ({metrics['false_negative_rate']*100:.2f}%)")
            
            # Additional metrics
            logger.info("\n📉 Additional Metrics:")
            if metrics.get('specificity') is not None:
                logger.info(f"   Specificity:  {metrics['specificity']:.4f} (True negative rate)")
            logger.info(f"   Sensitivity:  {metrics['sensitivity']:.4f} (True positive rate)")
        else:
            # Multi-class summary
            logger.info(f"\n📈 Multi-class Classification (Classes: {metrics.get('num_classes', 'N/A')})")
            logger.info("   Confusion matrix saved in classification report")
            logger.info(f"   Using weighted average for precision/recall/F1")
        
        logger.info("\n" + "=" * 80)
    
    @staticmethod
    def save_confusion_matrix_plot(metrics: Dict[str, Any], 
                                  output_path: Path,
                                  title: str = "Confusion Matrix"):
        """
        Save confusion matrix as a heatmap image.
        """
        try:
            cm = np.array(metrics['confusion_matrix'])
            
            plt.figure(figsize=(10, 8))
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                       xticklabels=['Benign', 'Malicious'],
                       yticklabels=['Benign', 'Malicious'],
                       cbar_kws={'label': 'Count'})
            
            plt.title(title, fontsize=16, fontweight='bold')
            plt.ylabel('True Label', fontsize=12)
            plt.xlabel('Predicted Label', fontsize=12)
            plt.tight_layout()
            
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            logger.info(f" Confusion matrix plot saved to {output_path}")
        except Exception as e:
            logger.warning(f"⚠️ Could not save confusion matrix plot: {e}")
    
    @staticmethod
    def save_roc_curve(y_true: np.ndarray, 
                      y_proba: np.ndarray, 
                      output_path: Path,
                      title: str = "ROC Curve"):
        """
        Save ROC curve plot.
        """
        try:
            fpr, tpr, thresholds = roc_curve(y_true, y_proba)
            auc = roc_auc_score(y_true, y_proba)
            
            plt.figure(figsize=(10, 8))
            plt.plot(fpr, tpr, color='blue', lw=2, 
                    label=f'ROC curve (AUC = {auc:.4f})')
            plt.plot([0, 1], [0, 1], color='red', lw=2, linestyle='--', 
                    label='Random classifier')
            
            plt.xlim([0.0, 1.0])
            plt.ylim([0.0, 1.05])
            plt.xlabel('False Positive Rate', fontsize=12)
            plt.ylabel('True Positive Rate', fontsize=12)
            plt.title(title, fontsize=16, fontweight='bold')
            plt.legend(loc="lower right", fontsize=10)
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            logger.info(f"ROC curve plot saved to {output_path}")
        except Exception as e:
            logger.warning(f"⚠️ Could not save ROC curve: {e}")


class EnhancedInferencePipeline:
    """
    Enhanced inference pipeline with attack success detection and comprehensive evaluation.
    """
    
    def __init__(self, models_dir: Path = config.MODELS_DIR):
        """Initialize the enhanced pipeline."""
        self.models_dir = Path(models_dir)
        
        # Model components
        self.signature_filter = None
        self.autoencoder = None
        self.ae_scaler = None
        self.ae_threshold = None
        self.ae_features = None
        self.bilstm = None
        self.meta_classifier = None
        
        # Attack success analyzer
        self.success_analyzer = AttackSuccessAnalyzer()
        
        # Evaluation metrics
        self.evaluator = EvaluationMetrics()
        
        logger.info("=" * 80)
        logger.info("INITIALIZING ENHANCED INFERENCE PIPELINE")
        logger.info("=" * 80)
        
        # Load all models
        self._load_all_models()
        
        logger.info(" Enhanced Inference Pipeline Ready!")
        logger.info("=" * 80)
    
    def _load_all_models(self):
        """Load all trained model components."""
        import time as _time
        import sys
        
        # ===== LAYER 1: SIGNATURE FILTER =====
        print("Loading Layer 1: Signature Filter...", flush=True)
        logger.info("\n📋 Loading Layer 1: Signature Filter...")
        _start = _time.time()
        try:
            self.signature_filter = SignatureFilter(
                patterns=True,
                blocklist=True,
                case_sensitive=False,
                confidence_threshold=0.1
            )
            
            patterns_path = self.models_dir / 'signature_filter_patterns.json'
            if patterns_path.exists():
                self.signature_filter.load_patterns(patterns_path)
            
            print(f"  Signature Filter loaded in {_time.time() - _start:.2f}s", flush=True)
            logger.info(f"   Loaded {len(self.signature_filter.patterns)} patterns in {_time.time() - _start:.2f}s")
        except Exception as e:
            logger.error(f"   Failed to load Signature Filter: {e}")
            raise
        
        # ===== LAYER 2: AUTOENCODER =====
        print("Loading Layer 2: Autoencoder...", flush=True)
        logger.info("\n🧠 Loading Layer 2: Autoencoder...")
        try:
            _start = _time.time()
            model_path = self.models_dir / 'autoencoder_model.h5'
            # compile=False skips TensorFlow graph recompilation (MUCH faster for inference)
            ae_model = keras.models.load_model(str(model_path), compile=False)
            print(f"  Autoencoder Keras model loaded in {_time.time() - _start:.2f}s", flush=True)
            logger.info(f"   Keras model loaded in {_time.time() - _start:.2f}s")
            
            scaler_path = self.models_dir / 'autoencoder_scaler.pkl'
            with open(scaler_path, 'rb') as f:
                self.ae_scaler = pickle.load(f)
            
            threshold_path = self.models_dir / 'autoencoder_threshold.pkl'
            with open(threshold_path, 'rb') as f:
                threshold_data = pickle.load(f)
                self.ae_threshold = threshold_data['threshold']
            
            metadata_path = self.models_dir / 'autoencoder_metadata.json'
            if metadata_path.exists():
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                    self.ae_features = metadata.get('feature_names', None)
            
            self.autoencoder = AdvancedAutoencoder(input_dim=ae_model.input_shape[1])
            self.autoencoder.model = ae_model
            self.autoencoder.scaler = self.ae_scaler
            self.autoencoder.threshold = self.ae_threshold
            
            print(f"  Autoencoder ready in {_time.time() - _start:.2f}s total", flush=True)
            logger.info(f"   ✓ Autoencoder ready")
        except Exception as e:
            logger.error(f"   Failed to load Autoencoder: {e}")
            raise
        
        # ===== LAYER 3: BI-LSTM =====
        print("Loading Layer 3: Bi-LSTM...", flush=True)
        logger.info("\n🔤 Loading Layer 3: Bi-LSTM...")
        try:
            _start = _time.time()
            bilstm_path = self.models_dir / 'bilstm_model.h5'
            self.bilstm = AdvancedBiLSTM.load(str(bilstm_path))
            print(f"  Bi-LSTM loaded in {_time.time() - _start:.2f}s", flush=True)
            logger.info(f"   Model loaded in {_time.time() - _start:.2f}s")
        except Exception as e:
            logger.error(f"   Failed to load Bi-LSTM: {e}")
            raise
        
        # ===== LAYER 4: META-CLASSIFIER =====
        print("Loading Layer 4: Meta-Classifier...", flush=True)
        logger.info("\n🎯 Loading Layer 4: Meta-Classifier...")
        try:
            _start = _time.time()
            meta_path = self.models_dir / 'rf_model.pkl'
            self.meta_classifier = MetaClassifier.load(meta_path)
            print(f"  Meta-Classifier loaded in {_time.time() - _start:.2f}s", flush=True)
            logger.info(f"   Model loaded in {_time.time() - _start:.2f}s")
        except Exception as e:
            logger.error(f"   Failed to load Meta-Classifier: {e}")
            raise
        
        print("All models loaded successfully!", flush=True)
    
    def _extract_flow_features(self, df: pd.DataFrame) -> np.ndarray:
        """Extract and align flow features to match trained model."""
        exclude_cols = [
            'label', 'attack_type', 'subtype', 'severity',
            'method', 'host', 'uri', 'full_url', 'user_agent', 'referer',
            'src_ip', 'dst_ip', 'src_port', 'dst_port', 
            'timestamp', 'flow_start', 'flow_end',
            'http_status', 'status_code',
            'flow_id', 'packet_id', 'id', 'index'
        ]
        
        expected_features = self.ae_scaler.n_features_in_
        
        if self.ae_features is not None and len(self.ae_features) > 0:
            logger.info(f"   Using saved feature names for exact matching")
            
            X_raw = np.zeros((len(df), len(self.ae_features)))
            for i, feat in enumerate(self.ae_features):
                if feat in df.columns:
                    X_raw[:, i] = df[feat].values
        else:
            logger.info(f"  Using numeric column alignment")
            
            numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
            exclude_cols_lower = [col.lower() for col in exclude_cols]
            feature_cols = [col for col in numeric_cols 
                          if col.lower() not in exclude_cols_lower]
            
            X_raw = df[feature_cols].values
        
        X_raw = np.nan_to_num(X_raw, nan=0.0, posinf=0.0, neginf=0.0)
        
        if X_raw.shape[1] > expected_features:
            X_raw = X_raw[:, :expected_features]
        elif X_raw.shape[1] < expected_features:
            padding = np.zeros((X_raw.shape[0], expected_features - X_raw.shape[1]))
            X_raw = np.hstack([X_raw, padding])
        
        X_scaled = self.ae_scaler.transform(X_raw)
        return X_scaled
    
    def _extract_payloads(self, df: pd.DataFrame) -> List[str]:
        """
        Extract HTTP payloads using vectorized operations (fast).
        """
        n_samples = len(df)
        payloads = [''] * n_samples
        
        # Pre-extract columns as arrays for fast processing
        has_full_url = 'full_url' in df.columns
        has_uri = 'uri' in df.columns
        has_method = 'method' in df.columns
        has_dst_port = 'dst_port' in df.columns
        has_protocol = 'protocol' in df.columns
        
        full_urls = df['full_url'].fillna('').astype(str).values if has_full_url else None
        uris = df['uri'].fillna('').astype(str).values if has_uri else None
        methods = df['method'].fillna('GET').astype(str).values if has_method else None
        dst_ports = df['dst_port'].fillna(0).values if has_dst_port else None
        protocols = df['protocol'].fillna('TCP').astype(str).values if has_protocol else None
        
        for idx in range(n_samples):
            # Priority: full_url > uri > method > protocol
            if full_urls is not None and full_urls[idx].strip():
                payloads[idx] = full_urls[idx]
            elif uris is not None and uris[idx].strip():
                method = methods[idx] if methods is not None else 'GET'
                payloads[idx] = f"{method} {uris[idx]}"
            elif methods is not None and methods[idx].strip():
                port = int(dst_ports[idx]) if dst_ports is not None else 443
                payloads[idx] = f"{methods[idx]} ENCRYPTED_TRAFFIC:{port}"
            else:
                proto = protocols[idx] if protocols is not None else 'TCP'
                port = int(dst_ports[idx]) if dst_ports is not None else 0
                payloads[idx] = f"{proto}_FLOW:{port}"
        
        return payloads
    
    def _batch_analyze_attack_success(self, df: pd.DataFrame, predictions: np.ndarray, 
                                      attack_classifications: List[Dict]) -> List[Dict]:
        """
        Vectorized batch attack success analysis - 100x faster than row-by-row.
        """
        n_samples = len(df)
        results = []
        
        # Pre-extract columns as numpy arrays
        http_status = df['http_status'].values if 'http_status' in df.columns else np.full(n_samples, np.nan)
        tot_bwd_pkts = df['tot_bwd_pkts'].values if 'tot_bwd_pkts' in df.columns else np.zeros(n_samples)
        totlen_bwd_pkts = df['totlen_bwd_pkts'].values if 'totlen_bwd_pkts' in df.columns else np.zeros(n_samples)
        fin_flag_cnt = df['fin_flag_cnt'].values if 'fin_flag_cnt' in df.columns else np.zeros(n_samples)
        rst_flag_cnt = df['rst_flag_cnt'].values if 'rst_flag_cnt' in df.columns else np.zeros(n_samples)
        flow_duration = df['flow_duration'].values if 'flow_duration' in df.columns else np.zeros(n_samples)
        methods = df['method'].values if 'method' in df.columns else np.array([''] * n_samples)
        
        # Vectorized score calculations
        scores = np.zeros(n_samples)
        
        # HTTP status scoring (vectorized)
        valid_status = ~np.isnan(http_status.astype(float))
        status_200 = valid_status & (http_status == 200)
        status_redirect = valid_status & np.isin(http_status, [301, 302, 303, 307, 308])
        status_error = valid_status & (http_status >= 400)
        
        scores = np.where(status_200, scores + 0.4, scores)
        scores = np.where(status_redirect, scores + 0.2, scores)
        scores = np.where(status_error, scores - 0.3, scores)
        
        # Backward packets scoring (vectorized)
        scores = np.where(tot_bwd_pkts > 5, scores + 0.3, scores)
        scores = np.where(totlen_bwd_pkts > 1000, scores + 0.2, scores)
        
        # Connection termination scoring (vectorized)
        normal_term = (fin_flag_cnt > 0) & (rst_flag_cnt == 0)
        scores = np.where(normal_term, scores + 0.15, scores)
        scores = np.where(rst_flag_cnt > 0, scores - 0.2, scores)
        
        # Flow duration scoring
        scores = np.where(flow_duration > 1.0, scores + 0.1, scores)
        
        # Normalize scores
        scores = np.clip(scores, 0.0, 1.0)
        
        # Build results
        for idx in range(n_samples):
            if not predictions[idx]:
                results.append({
                    'attack_detected': False,
                    'attack_outcome': 'BENIGN',
                    'success_confidence': 0.0,
                    'reasoning': ['No attack detected']
                })
            else:
                # Determine outcome based on score
                score = float(scores[idx])
                attack_type = attack_classifications[idx].get('attack_type', 'unknown')
                
                # Attack-specific bonuses (simplified for speed)
                if attack_type == 'sql_injection' and totlen_bwd_pkts[idx] > 5000:
                    score = min(score + 0.3, 1.0)
                elif attack_type in ['lfi', 'rfi', 'directory_traversal'] and totlen_bwd_pkts[idx] > 2000:
                    score = min(score + 0.4, 1.0)
                elif attack_type == 'ssrf' and totlen_bwd_pkts[idx] > 500:
                    score = min(score + 0.4, 1.0)
                elif attack_type == 'webshell' and str(methods[idx]).upper() == 'POST':
                    score = min(score + 0.5, 1.0)
                
                if score >= 0.7:
                    outcome = 'SUCCESSFUL_ATTACK'
                elif score >= 0.4:
                    outcome = 'LIKELY_SUCCESSFUL'
                elif score >= 0.2:
                    outcome = 'PARTIALLY_SUCCESSFUL'
                else:
                    outcome = 'FAILED_ATTACK'
                
                results.append({
                    'attack_detected': True,
                    'attack_outcome': outcome,
                    'success_confidence': round(score, 4),
                    'reasoning': ['Batch analyzed']
                })
        
        return results
    
    def generate_detailed_json_report(self,
                                    input_path: Path,
                                    output_path: Path,
                                    include_layer_details: bool = True,
                                    include_true_labels: bool = True,
                                    save_visualizations: bool = True) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Generate detailed JSON report WITH evaluation metrics.
        
        Returns:
            Tuple of (detailed_reports, evaluation_metrics)
        """
        logger.info("=" * 80)
        logger.info(f"GENERATING DETAILED JSON REPORT: {input_path}")
        logger.info("=" * 80)
        
        # Load CSV
        df = pd.read_csv(input_path)
        logger.info(f" Loaded {len(df)} rows")
        
        # Check for labels
        has_labels = 'label' in df.columns
        if has_labels:
            true_labels = df['label'].values
            df_inference = df.drop(columns=['label', 'attack_type', 'subtype', 'severity'], errors='ignore')
        else:
            true_labels = None
            df_inference = df.copy()
        
        # Get payloads and flow features
        payloads = self._extract_payloads(df_inference)
        flow_features = self._extract_flow_features(df_inference)
        
        logger.info("\n🔍 Running inference with attack success analysis...")
        
        # === LAYER 1-4: Inference ===
        logger.info("  Layer 1: Signature Filter...")
        sig_results = self.signature_filter.filter_batch(
            payloads=np.array(payloads),
            labels=None,
            use_threading=True,
            max_workers=4
        )
        
        logger.info("  Layer 2: Autoencoder...")
        ae_results = self.autoencoder.predict(flow_features)
        
        logger.info("  Layer 3: Bi-LSTM...")
        sequences = self.bilstm.texts_to_sequences(payloads)
        lstm_results = self.bilstm.predict(sequences)
        
        logger.info("  Layer 4: Meta-Classifier...")
        sig_formatted = {
            'predictions': sig_results['predictions'],
            'matched_patterns': sig_results['matched_patterns']
        }
        ae_formatted = {
            'predictions': ae_results['predictions'],
            'reconstruction_errors': ae_results['reconstruction_errors'],
            'anomaly_scores': ae_results['anomaly_scores']
        }
        lstm_formatted = {
            'predictions': lstm_results['predictions'],
            'probabilities': lstm_results['probabilities'],
            'confidence': lstm_results['confidence']
        }
        
        meta_results = self.meta_classifier.predict(
            signature_results=sig_formatted,
            autoencoder_results=ae_formatted,
            bilstm_results=lstm_formatted,
            threshold=0.5
        )
        
        logger.info("\n🎯 Building reports using vectorized batch processing...")
        
        # =====================================================================
        # VECTORIZED BATCH PROCESSING - 100x faster than row-by-row
        # =====================================================================
        n_samples = len(df)
        
        # Pre-extract all columns as numpy arrays for fast access
        src_ips = df['src_ip'].values if 'src_ip' in df.columns else np.array(['unknown'] * n_samples)
        methods = df['method'].values if 'method' in df.columns else np.array(['TCP'] * n_samples)
        dst_ports = df['dst_port'].values if 'dst_port' in df.columns else np.zeros(n_samples)
        full_urls = df['full_url'].fillna('').values if 'full_url' in df.columns else np.array([''] * n_samples)
        hosts = df['host'].fillna('').values if 'host' in df.columns else np.array([''] * n_samples)
        uris = df['uri'].fillna('').values if 'uri' in df.columns else np.array([''] * n_samples)
        
        # Network evidence columns - extract once
        evidence_cols = ['http_status', 'flow_duration', 'tot_bwd_pkts', 'totlen_bwd_pkts', 'rst_flag_cnt', 'fin_flag_cnt']
        evidence_data = {}
        for col in evidence_cols:
            if col in df.columns:
                evidence_data[col] = df[col].values
        
        # Pre-compute vectorized verdicts and risk levels
        predictions = meta_results['predictions']
        probabilities = meta_results['probabilities']
        verdicts = np.where(predictions, 'MALICIOUS', 'BENIGN')
        risk_levels = np.where(probabilities > 0.8, 'High risk', 
                              np.where(probabilities > 0.5, 'Moderate risk', 'Low risk'))
        
        # Pre-compute layer results as arrays
        sig_preds = sig_results['predictions']
        sig_confs = np.round(sig_results['confidences'].astype(float), 4)
        ae_preds = ae_results['predictions']
        ae_errors = ae_results['reconstruction_errors']
        ae_scores = np.round(ae_results['anomaly_scores'].astype(float), 4)
        lstm_preds = lstm_results['predictions']
        lstm_probs = np.round(lstm_results['probabilities'].astype(float), 4)
        lstm_confs = np.round(lstm_results['confidence'].astype(float), 4)
        
        # Vectorized attack classification - batch process all patterns
        logger.info("  Batch classifying attacks...")
        attack_classifications = []
        pattern_strs = []
        for patterns in sig_results['matched_patterns']:
            attack_classifications.append(self.success_analyzer.classify_attack(patterns))
            pattern_strs.append(patterns[0].split(':', 1)[1] if patterns else "NONE")
        
        # Vectorized success analysis - compute scores in batch
        logger.info("  Batch analyzing attack success...")
        success_analyses = self._batch_analyze_attack_success(
            df, predictions, attack_classifications
        )
        
        # Build reports using list comprehension (much faster than append loop)
        logger.info("  Assembling JSON reports...")
        detailed_reports = []
        
        # Use zip for fast iteration without pandas overhead
        for idx in range(n_samples):
            # Build network evidence dict
            network_evidence = {}
            for col in evidence_cols:
                if col in evidence_data:
                    val = evidence_data[col][idx]
                    if pd.notna(val):
                        network_evidence[col] = float(val) if isinstance(val, (float, np.floating)) else int(val)
            
            report = {
                "packet_id": f"{src_ips[idx]}_{methods[idx]}_{dst_ports[idx]}.{idx}",
                "final_verdict": verdicts[idx],
                "confidence_score": round(float(probabilities[idx]), 4),
                "attack_classification": attack_classifications[idx],
                "attack_execution_result": success_analyses[idx],
                "layer_details": {
                    "layer_1_signature": {
                        "detected": bool(sig_preds[idx]),
                        "pattern": pattern_strs[idx],
                        "confidence": float(sig_confs[idx]),
                        "num_patterns_matched": len(sig_results['matched_patterns'][idx])
                    },
                    "layer_2_autoencoder": {
                        "status": "Anomaly" if ae_preds[idx] else "Normal",
                        "reconstruction_error": float(ae_errors[idx]),
                        "threshold": float(self.ae_threshold),
                        "anomaly_score": float(ae_scores[idx])
                    },
                    "layer_3_bilstm": {
                        "detected": bool(lstm_preds[idx]),
                        "prob_malicious": float(lstm_probs[idx]),
                        "confidence": float(lstm_confs[idx]),
                        "context": f"Deep learning analysis: {risk_levels[idx]}"
                    }
                },
                "network_evidence": network_evidence,
                "original_data": {
                    "full_url": str(full_urls[idx]),
                    "method": str(methods[idx]),
                    "host": str(hosts[idx]),
                    "uri": str(uris[idx])
                }
            }
            
            if has_labels and include_true_labels:
                report["true_label"] = int(true_labels[idx])
                report["true_label_str"] = "MALICIOUS" if true_labels[idx] == 1 else "BENIGN"
                report["prediction_correct"] = bool(predictions[idx] == true_labels[idx])
            
            detailed_reports.append(report)
        
        logger.info(f"  ✓ Generated {n_samples} reports")
        
        # === NEW: CALCULATE EVALUATION METRICS ===
        evaluation_metrics = None
        if has_labels:
            logger.info("\n📊 Calculating evaluation metrics...")
            
            y_true = true_labels
            y_pred = meta_results['predictions']
            y_proba = meta_results['probabilities']
            
            evaluation_metrics = self.evaluator.calculate_all_metrics(
                y_true=y_true,
                y_pred=y_pred,
                y_proba=y_proba
            )
            
            # Print metrics to console
            self.evaluator.print_metrics(evaluation_metrics, 
                                        title="Overall System Performance")
            
            # Save visualizations if requested
            if save_visualizations:
                output_dir = output_path.parent
                
                # Confusion matrix
                cm_path = output_dir / f"{output_path.stem}_confusion_matrix.png"
                self.evaluator.save_confusion_matrix_plot(
                    evaluation_metrics, 
                    cm_path,
                    title="Hybrid IDS Confusion Matrix"
                )
                
                # ROC curve
                roc_path = output_dir / f"{output_path.stem}_roc_curve.png"
                self.evaluator.save_roc_curve(
                    y_true, 
                    y_proba,
                    roc_path,
                    title="Hybrid IDS ROC Curve"
                )
        
        # Save JSON report
        logger.info(f"\n💾 Saving enhanced JSON report...")
        output_data = {
            "metadata": {
                "total_samples": len(df),
                "malicious_detected": int(np.sum(meta_results['predictions'])),
                "benign_detected": int(len(df) - np.sum(meta_results['predictions'])),
                "has_ground_truth": has_labels
            },
            "evaluation_metrics": evaluation_metrics,
            "predictions": detailed_reports
        }
        
        with open(output_path, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        logger.info(f"✅ Enhanced JSON report saved to {output_path}")
        
        # Print sample
        logger.info("\n📄 Sample Enhanced Report (first record):")
        logger.info("-" * 80)
        print(json.dumps(detailed_reports[0], indent=2))
        logger.info("-" * 80)
        
        # Attack success statistics
        successful_attacks = sum(1 for r in detailed_reports 
                                if r['attack_execution_result']['attack_outcome'] == 'SUCCESSFUL_ATTACK')
        malicious_count = sum(1 for r in detailed_reports if r['final_verdict'] == 'MALICIOUS')
        
        logger.info(f"\n📊 Attack Success Analysis:")
        logger.info(f"   Total Malicious: {malicious_count}")
        logger.info(f"   Successful Attacks: {successful_attacks}")
        if malicious_count > 0:
            logger.info(f"   Success Rate: {successful_attacks/malicious_count*100:.1f}%")
        
        return detailed_reports, evaluation_metrics


def main():
    """Main CLI interface."""
    parser = argparse.ArgumentParser(
        description='Enhanced Hybrid IDS with Attack Success Detection and Evaluation Metrics'
    )
    
    parser.add_argument('--input', '-i', type=str, required=True,
                       help='Input CSV file path')
    parser.add_argument('--output', '-o', type=str, required=True,
                       help='Output JSON file path')
    parser.add_argument('--models-dir', type=str, default='models',
                       help='Directory containing trained models')
    parser.add_argument('--evaluate', action='store_true',
                       help='Include true labels and evaluation (requires label column in CSV)')
    parser.add_argument('--no-visualizations', action='store_true',
                       help='Skip saving visualization plots')
    
    args = parser.parse_args()
    
    try:
        # Initialize enhanced pipeline
        logger.info("🚀 Initializing Enhanced Inference Pipeline...")
        pipeline = EnhancedInferencePipeline(models_dir=Path(args.models_dir))
        
        # Generate enhanced JSON report with evaluation
        detailed_reports, metrics = pipeline.generate_detailed_json_report(
            input_path=Path(args.input),
            output_path=Path(args.output),
            include_true_labels=args.evaluate,
            save_visualizations=not args.no_visualizations
        )
        
        logger.info("\n" + "=" * 80)
        logger.info(" ENHANCED INFERENCE COMPLETED SUCCESSFULLY!")
        logger.info("=" * 80)
        
        if metrics:
            logger.info(f"\n📈 Summary:")
            logger.info(f"   Accuracy:  {metrics['accuracy']:.2%}")
            logger.info(f"   Precision: {metrics['precision']:.2%}")
            logger.info(f"   Recall:    {metrics['recall']:.2%}")
            logger.info(f"   F1-Score:  {metrics['f1_score']:.2%}")
        
    except Exception as e:
        logger.error(f" Inference failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())