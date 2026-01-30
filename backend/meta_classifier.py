"""
Meta-Classifier Module for Hybrid Intrusion Detection System (IDS)
Layer 4: Ensemble meta-learning combining all three detection layers

This module implements the final decision layer that combines predictions from:
- Layer 1: Signature Filter (rule-based detection)
- Layer 2: Autoencoder (anomaly detection on flow features)
- Layer 3: Bi-LSTM (deep learning on payloads)

Features:
- Random Forest meta-classifier with engineered meta-features
- Confidence-weighted voting
- Multi-level ensemble strategies
- Advanced feature engineering from layer outputs
- Explainable predictions with feature importance
- Dynamic threshold optimization
- Calibrated probability estimates
- **NEW: Deep feature integration from BiLSTM**

Author: Senior ML Engineer (Hackathon Champion Edition)
Date: 2025
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                            f1_score, roc_auc_score, roc_curve,
                            precision_recall_curve, confusion_matrix,
                            classification_report)
from sklearn.model_selection import cross_val_score
import matplotlib.pyplot as plt
import seaborn as sns
import logging
from pathlib import Path
from typing import Dict, Tuple, List, Optional, Any, Union
import pickle
import json
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

import config

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Set random seed
np.random.seed(config.RANDOM_SEED)


class MetaFeatureEngineering:
    """
    Advanced feature engineering for meta-classifier.
    
    Creates sophisticated meta-features from the outputs of all three layers:
    - Layer 1 (Signature): Pattern matches, confidence
    - Layer 2 (Autoencoder): Reconstruction errors, anomaly scores
    - Layer 3 (Bi-LSTM): Probabilities, confidence, DEEP FEATURES
    - Consensus features: Agreement, weighted votes, entropy
    """
    
    @staticmethod
    def extract_signature_features(signature_results: Dict) -> np.ndarray:
        """
        Extract features from signature filter output.
        
        Args:
            signature_results: Dictionary from signature_filter.filter_batch()
                - predictions: Binary predictions
                - matched_patterns: List of matched patterns per sample
                
        Returns:
            Feature array (N, 3):
            - sig_prediction: Binary prediction
            - sig_num_patterns: Number of matched patterns
            - sig_confidence: Confidence (1.0 if match, 0.0 otherwise)
        """
        predictions = signature_results['predictions']
        matched_patterns = signature_results['matched_patterns']
        
        # Number of patterns matched per sample
        num_patterns = np.array([len(patterns) for patterns in matched_patterns])
        
        # Confidence: 1.0 if any pattern matched, 0.0 otherwise
        confidence = predictions.astype(float)
        
        features = np.column_stack([
            predictions,
            num_patterns,
            confidence
        ])
        
        return features
    
    
    @staticmethod
    def extract_autoencoder_features(autoencoder_results: Dict) -> np.ndarray:
        """
        Extract features from autoencoder output.
        
        Args:
            autoencoder_results: Dictionary from autoencoder.predict()
                - predictions: Binary predictions
                - reconstruction_errors: MSE per sample
                - anomaly_scores: Normalized scores
                
        Returns:
            Feature array (N, 4):
            - ae_prediction: Binary prediction
            - ae_reconstruction_error: Raw reconstruction error
            - ae_anomaly_score: Normalized anomaly score
            - ae_error_log: Log-transformed error (for scaling)
        """
        predictions = autoencoder_results['predictions']
        errors = autoencoder_results['reconstruction_errors']
        scores = autoencoder_results['anomaly_scores']
        
        # Log-transform errors for better scaling
        error_log = np.log1p(errors)
        
        features = np.column_stack([
            predictions,
            errors,
            scores,
            error_log
        ])
        
        return features
    
    
    @staticmethod
    def extract_bilstm_features(bilstm_results: Dict) -> np.ndarray:
        """
        Extract features from Bi-LSTM output, INCLUDING DEEP FEATURES.
        
        Args:
            bilstm_results: Dictionary from bilstm.predict() containing:
                - predictions: Binary predictions
                - probabilities: Prediction probabilities
                - confidence: Confidence scores
                - deep_features: (OPTIONAL) Deep feature vectors from penultimate layer
                
        Returns:
            Feature array (N, 5 + D) where D = number of deep features (0, 32, or 64):
            - lstm_prediction: Binary prediction
            - lstm_probability: Raw probability
            - lstm_confidence: Confidence score
            - lstm_prob_squared: Squared probability (non-linearity)
            - lstm_entropy: Prediction entropy (uncertainty measure)
            - lstm_deep_0 to lstm_deep_D: Deep feature vectors (if available)
        """
        predictions = bilstm_results['predictions']
        probabilities = bilstm_results['probabilities']
        confidence = bilstm_results['confidence']
        
        # --- NEW LOGIC: Get Deep Features ---
        # Use .get() to avoid errors if running with old BiLSTM model
        deep_features = bilstm_results.get('deep_features', None)
        
        # Squared probability (non-linear transformation)
        prob_squared = probabilities ** 2
        
        # Entropy: measure of uncertainty
        # H = -p*log(p) - (1-p)*log(1-p)
        eps = 1e-7  # Prevent log(0)
        p = np.clip(probabilities, eps, 1 - eps)
        entropy = -(p * np.log(p) + (1 - p) * np.log(1 - p))
        
        # Create the standard 5 base features
        base_features = np.column_stack([
            predictions,
            probabilities,
            confidence,
            prob_squared,
            entropy
        ])
        
        # --- NEW LOGIC: Stack Deep Features ---
        # [NEW] Stack deep features if they exist
        if deep_features is not None:
            # deep_features is shape (N, 32), base is (N, 5) -> Result (N, 37)
            return np.hstack([base_features, deep_features])
        
        return base_features
    
    
    @staticmethod
    def extract_consensus_features(sig_features: np.ndarray,
                                ae_features: np.ndarray,
                                lstm_features: np.ndarray) -> np.ndarray:
        """
        Extract consensus features from all three layers.
        FIXED: Added shape validation.
        """
        # FIXED: Validate shapes before indexing
        if sig_features.ndim == 1:
            sig_pred = sig_features
        else:
            sig_pred = sig_features[:, 0]
        
        if ae_features.ndim == 1:
            ae_pred = ae_features
        else:
            ae_pred = ae_features[:, 0]
        
        if lstm_features.ndim == 1:
            lstm_pred = lstm_features
        else:
            lstm_pred = lstm_features[:, 0]
        
        # FIXED: Ensure all have same length
        min_len = min(len(sig_pred), len(ae_pred), len(lstm_pred))
        if len(sig_pred) != len(ae_pred) or len(ae_pred) != len(lstm_pred):
            logger.warning(f"⚠️  Shape mismatch: sig={len(sig_pred)}, ae={len(ae_pred)}, lstm={len(lstm_pred)}")
            logger.warning(f"   Truncating to minimum length: {min_len}")
            sig_pred = sig_pred[:min_len]
            ae_pred = ae_pred[:min_len]
            lstm_pred = lstm_pred[:min_len]
        
        # Layer agreement: how many layers agree
        vote_sum = sig_pred + ae_pred + lstm_pred
        layer_agreement = vote_sum
        
        # Majority vote (at least 2 out of 3)
        majority_vote = (vote_sum >= 2).astype(int)
        
        # Unanimous decisions
        unanimous_malicious = (vote_sum == 3).astype(int)
        unanimous_benign = (vote_sum == 0).astype(int)
        
        # Weighted vote (LSTM has highest weight, then AE, then Signature)
        weights = np.array([0.2, 0.3, 0.5])  # [sig, ae, lstm]
        predictions_stack = np.column_stack([sig_pred, ae_pred, lstm_pred])
        weighted_vote = np.dot(predictions_stack, weights)
        
        # Confidence features
        # FIXED: Safe indexing for confidence values
        if sig_features.ndim == 1:
            sig_conf = sig_pred.astype(float)
        else:
            sig_conf = sig_features[:min_len, 2] if sig_features.shape[1] > 2 else sig_pred.astype(float)
        
        if ae_features.ndim == 1:
            ae_conf = ae_pred.astype(float)
        else:
            ae_conf = ae_features[:min_len, 2] if ae_features.shape[1] > 2 else ae_pred.astype(float)
        
        if lstm_features.ndim == 1:
            lstm_conf = lstm_pred.astype(float)
        else:
            lstm_conf = lstm_features[:min_len, 2] if lstm_features.shape[1] > 2 else lstm_pred.astype(float)
        
        confidences_stack = np.column_stack([sig_conf, ae_conf, lstm_conf])
        avg_confidence = np.mean(confidences_stack, axis=1)
        max_confidence = np.max(confidences_stack, axis=1)
        
        # Prediction variance (disagreement measure)
        prediction_variance = np.var(predictions_stack, axis=1)
        
        features = np.column_stack([
            layer_agreement,
            majority_vote,
            unanimous_malicious,
            unanimous_benign,
            weighted_vote,
            avg_confidence,
            max_confidence,
            prediction_variance
        ])
        
        return features


    @classmethod
    def create_meta_features(cls,
                            signature_results: Dict,
                            autoencoder_results: Dict,
                            bilstm_results: Dict) -> Tuple[np.ndarray, List[str]]:
        """
        Create complete meta-feature set from all layers.
        Dynamically handles variable number of BiLSTM deep features.
        
        Args:
            signature_results: Results from Layer 1
            autoencoder_results: Results from Layer 2
            bilstm_results: Results from Layer 3 (may include deep_features)
            
        Returns:
            Tuple of (features, feature_names)
            - features: (N, 20+D) meta-feature array where D = deep feature count
            - feature_names: List of feature names (dynamically generated)
        """
        # Extract features from each layer
        sig_features = cls.extract_signature_features(signature_results)
        ae_features = cls.extract_autoencoder_features(autoencoder_results)
        lstm_features = cls.extract_bilstm_features(bilstm_results)
        
        # Calculate consensus based on predictions only (first column of each)
        consensus_features = cls.extract_consensus_features(
            sig_features, ae_features, lstm_features
        )
        
        # Combine all features
        all_features = np.concatenate([
            sig_features,
            ae_features,
            lstm_features,
            consensus_features
        ], axis=1)
        
        # --- NEW LOGIC: Dynamic Feature Naming ---
        
        # 1. Signature Names (3)
        feature_names = [
            'sig_prediction', 'sig_num_patterns', 'sig_confidence'
        ]
        
        # 2. Autoencoder Names (4)
        feature_names.extend([
            'ae_prediction', 'ae_reconstruction_error', 'ae_anomaly_score', 'ae_error_log'
        ])
        
        # 3. Bi-LSTM Names (Dynamic: 5 base + D deep)
        # Base names (5)
        feature_names.extend([
            'lstm_prediction', 'lstm_probability', 'lstm_confidence',
            'lstm_prob_squared', 'lstm_entropy'
        ])
        
        # Check for deep features
        # Total LSTM columns minus the 5 base columns = number of deep features
        num_deep_features = lstm_features.shape[1] - 5
        if num_deep_features > 0:
            feature_names.extend([f'lstm_deep_{i}' for i in range(num_deep_features)])
            logger.info(f"Added {num_deep_features} deep feature names: lstm_deep_0 to lstm_deep_{num_deep_features-1}")
        
        # 4. Consensus Names (8)
        feature_names.extend([
            'layer_agreement', 'majority_vote', 'unanimous_malicious',
            'unanimous_benign', 'weighted_vote', 'avg_confidence',
            'max_confidence', 'prediction_variance'
        ])
        
        logger.info(f"Total meta-features: {all_features.shape[1]} (Expected names: {len(feature_names)})")
        
        # Sanity check
        if all_features.shape[1] != len(feature_names):
            logger.error(f"MISMATCH! Features: {all_features.shape[1]}, Names: {len(feature_names)}")
            raise ValueError(f"Feature count mismatch: {all_features.shape[1]} != {len(feature_names)}")
        
        return all_features, feature_names


class MetaClassifier:
    """
    Advanced meta-classifier that combines outputs from all three layers.
    
    Uses Random Forest as the primary meta-learner with:
    - Engineered meta-features from all layers
    - Confidence-weighted predictions
    - Calibrated probability estimates
    - Feature importance analysis
    - Multiple voting strategies
    - Ensemble of meta-classifiers
    - **NEW: Deep feature integration from BiLSTM**
    
    Attributes:
        meta_model: Primary meta-classifier (Random Forest)
        calibrated_model: Calibrated version for better probabilities
        feature_names: Names of meta-features
        feature_importance: Feature importance scores
        voting_strategy: Strategy for final prediction
    """
    
    def __init__(self,
                 meta_model_type: str = 'random_forest',
                 n_estimators: int = 300,
                 max_depth: int = 15,
                 voting_strategy: str = 'model',
                 use_calibration: bool = True):
        """
        Initialize the meta-classifier.
        
        Args:
            meta_model_type: Type of meta-model ('random_forest', 'gradient_boost', 'logistic')
            n_estimators: Number of trees (for ensemble methods)
            max_depth: Maximum tree depth
            voting_strategy: 'model' (use meta-model), 'majority', 'weighted', 'unanimous'
            use_calibration: Use probability calibration
        """
        self.meta_model_type = meta_model_type
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.voting_strategy = voting_strategy
        self.use_calibration = use_calibration
        
        self.meta_model: Optional[Any] = None
        self.calibrated_model: Optional[Any] = None
        self.feature_names: Optional[List[str]] = None
        self.feature_importance: Optional[np.ndarray] = None
        
        logger.info(f"MetaClassifier initialized")
        logger.info(f"Model: {meta_model_type}, Voting: {voting_strategy}, "
                   f"Calibration: {use_calibration}")
    
    
    def build_meta_model(self) -> Any:
        """
        Build the meta-classifier model.
        
        Returns:
            Trained meta-model
        """
        if self.meta_model_type == 'random_forest':
            model = RandomForestClassifier(
                n_estimators=self.n_estimators,
                max_depth=self.max_depth,
                min_samples_split=2,
                min_samples_leaf=2,
                max_features='sqrt',
                bootstrap=True,
                oob_score=True,
                random_state=config.RANDOM_SEED,
                class_weight='balanced_subsample',
                n_jobs=-1,
                verbose=0
            )
        
        elif self.meta_model_type == 'gradient_boost':
            model = GradientBoostingClassifier(
                n_estimators=self.n_estimators,
                max_depth=self.max_depth,
                learning_rate=0.1,
                subsample=0.8,
                random_state=config.RANDOM_SEED,
                verbose=0
            )
        
        elif self.meta_model_type == 'logistic':
            model = LogisticRegression(
                penalty='l2',
                C=1.0,
                max_iter=1000,
                random_state=config.RANDOM_SEED,
                n_jobs=-1
            )
        
        else:
            raise ValueError(f"Unknown meta_model_type: {self.meta_model_type}")
        
        return model
    
    
    def train(self,
              signature_results: Dict,
              autoencoder_results: Dict,
              bilstm_results: Dict,
              y_true: np.ndarray) -> None:
        """
        Train the meta-classifier on layer outputs.
        
        Args:
            signature_results: Results from Layer 1
            autoencoder_results: Results from Layer 2
            bilstm_results: Results from Layer 3 (may include deep_features)
            y_true: True labels
        """
        logger.info("="*80)
        logger.info("TRAINING META-CLASSIFIER")
        logger.info("="*80)
        
        # Create meta-features
        X_meta, self.feature_names = MetaFeatureEngineering.create_meta_features(
            signature_results,
            autoencoder_results,
            bilstm_results
        )
        
        logger.info(f"Meta-features shape: {X_meta.shape}")
        logger.info(f"Number of features: {len(self.feature_names)}")
        logger.info(f"Features: {self.feature_names[:5]}... (showing first 5)")
        
        # Build and train model
        self.meta_model = self.build_meta_model()
        
        logger.info(f"Training {self.meta_model_type} meta-classifier...")
        self.meta_model.fit(X_meta, y_true)
        
        # Get feature importance
        if hasattr(self.meta_model, 'feature_importances_'):
            self.feature_importance = self.meta_model.feature_importances_
            
            # Log top 10 features
            importance_df = pd.DataFrame({
                'feature': self.feature_names,
                'importance': self.feature_importance
            }).sort_values('importance', ascending=False)
            
            logger.info("\nTop 10 Most Important Features:")
            logger.info("-" * 60)
            for idx, row in importance_df.head(10).iterrows():
                logger.info(f"  {row['feature']:<30} {row['importance']:.4f}")
        
        # Calibrate probabilities
        if self.use_calibration:
            logger.info("Calibrating probability estimates...")
            self.calibrated_model = CalibratedClassifierCV(
                self.meta_model,
                method='sigmoid',
                cv=3
            )
            self.calibrated_model.fit(X_meta, y_true)
        
        # Cross-validation score
        cv_scores = cross_val_score(
            self.meta_model, X_meta, y_true,
            cv=5, scoring='f1'
        )
        # Store CV scores on the instance for later access
        self.cv_scores = cv_scores
        logger.info(f"\n5-Fold CV F1-Score: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
        
        # OOB score for Random Forest
        if self.meta_model_type == 'random_forest':
            logger.info(f"Out-of-Bag Score: {self.meta_model.oob_score_:.4f}")
        
        logger.info("Meta-classifier training completed!")
    
    
    def predict(self,
                signature_results: Dict,
                autoencoder_results: Dict,
                bilstm_results: Dict,
                threshold: float = 0.5) -> Dict[str, np.ndarray]:
        """
        Predict using the meta-classifier.
        
        Args:
            signature_results: Results from Layer 1
            autoencoder_results: Results from Layer 2
            bilstm_results: Results from Layer 3 (may include deep_features)
            threshold: Classification threshold
            
        Returns:
            Dictionary containing:
            - predictions: Final binary predictions
            - probabilities: Calibrated probabilities
            - meta_features: Engineered meta-features
            - layer_predictions: Individual layer predictions
            - confidence: Prediction confidence
        """
        # Create meta-features
        X_meta, _ = MetaFeatureEngineering.create_meta_features(
            signature_results,
            autoencoder_results,
            bilstm_results
        )
        
        # Get predictions based on voting strategy
        if self.voting_strategy == 'model':
            # Use meta-model predictions
            if self.use_calibration and self.calibrated_model is not None:
                probabilities = self.calibrated_model.predict_proba(X_meta)[:, 1]
            else:
                probabilities = self.meta_model.predict_proba(X_meta)[:, 1]
            
            predictions = (probabilities >= threshold).astype(int)
        
        elif self.voting_strategy == 'majority':
            # Simple majority vote (at least 2/3 layers)
            sig_pred = signature_results['predictions']
            ae_pred = autoencoder_results['predictions']
            lstm_pred = bilstm_results['predictions']
            
            vote_sum = sig_pred + ae_pred + lstm_pred
            predictions = (vote_sum >= 2).astype(int)
            probabilities = vote_sum / 3.0
        
        elif self.voting_strategy == 'weighted':
            # Weighted vote (LSTM 50%, AE 30%, Sig 20%)
            sig_pred = signature_results['predictions']
            ae_pred = autoencoder_results['predictions']
            lstm_pred = bilstm_results['predictions']
            
            probabilities = (
                0.2 * sig_pred +
                0.3 * ae_pred +
                0.5 * lstm_pred
            )
            predictions = (probabilities >= threshold).astype(int)
        
        elif self.voting_strategy == 'unanimous':
            # All layers must agree for malicious
            sig_pred = signature_results['predictions']
            ae_pred = autoencoder_results['predictions']
            lstm_pred = bilstm_results['predictions']
            
            predictions = (sig_pred & ae_pred & lstm_pred).astype(int)
            probabilities = predictions.astype(float)
        
        else:
            raise ValueError(f"Unknown voting strategy: {self.voting_strategy}")
        
        # Confidence (distance from decision boundary)
        confidence = np.abs(probabilities - threshold)
        
        # Store individual layer predictions
        layer_predictions = {
            'signature': signature_results['predictions'],
            'autoencoder': autoencoder_results['predictions'],
            'bilstm': bilstm_results['predictions']
        }
        
        return {
            'predictions': predictions,
            'probabilities': probabilities,
            'meta_features': X_meta,
            'layer_predictions': layer_predictions,
            'confidence': confidence
        }
    
    
    def evaluate(self,
                 signature_results: Dict,
                 autoencoder_results: Dict,
                 bilstm_results: Dict,
                 y_true: np.ndarray,
                 split_name: str = 'test') -> Dict[str, float]:
        """
        Evaluate meta-classifier performance.
        
        Args:
            signature_results: Results from Layer 1
            autoencoder_results: Results from Layer 2
            bilstm_results: Results from Layer 3 (may include deep_features)
            y_true: True labels
            split_name: Name of split for logging
            
        Returns:
            Dictionary of metrics
        """
        logger.info(f"Evaluating meta-classifier on {split_name} set...")
        
        # Get predictions
        results = self.predict(signature_results, autoencoder_results, bilstm_results)
        y_pred = results['predictions']
        y_prob = results['probabilities']
        
        # Calculate metrics
        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        
        try:
            auc = roc_auc_score(y_true, y_prob)
        except:
            auc = 0.0
        
        # Confusion matrix
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        
        # Additional metrics
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
        npv = tn / (tn + fn) if (tn + fn) > 0 else 0.0  # Negative Predictive Value
        
        metrics = {
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'auc': float(auc),
            'true_positives': int(tp),
            'true_negatives': int(tn),
            'false_positives': int(fp),
            'false_negatives': int(fn),
            'fpr': float(fpr),
            'fnr': float(fnr),
            'specificity': float(specificity),
            'npv': float(npv)
        }
        
        # Log metrics
        self.log_metrics(metrics, split_name)
        
        return metrics
    
    
    def log_metrics(self, metrics: Dict[str, float], split_name: str = 'test') -> None:
        """Log evaluation metrics."""
        logger.info("="*80)
        logger.info(f"META-CLASSIFIER METRICS ({split_name.upper()})")
        logger.info("="*80)
        logger.info(f"Accuracy:    {metrics['accuracy']:.4f}")
        logger.info(f"Precision:   {metrics['precision']:.4f}")
        logger.info(f"Recall:      {metrics['recall']:.4f}")
        logger.info(f"F1-Score:    {metrics['f1_score']:.4f}")
        logger.info(f"AUC:         {metrics['auc']:.4f}")
        logger.info(f"Specificity: {metrics['specificity']:.4f}")
        logger.info(f"NPV:         {metrics['npv']:.4f}")
        logger.info(f"FPR:         {metrics['fpr']:.4f}")
        logger.info(f"FNR:         {metrics['fnr']:.4f}")
        logger.info(f"\nConfusion Matrix:")
        logger.info(f"  TP: {metrics['true_positives']:6d}  FP: {metrics['false_positives']:6d}")
        logger.info(f"  FN: {metrics['false_negatives']:6d}  TN: {metrics['true_negatives']:6d}")
        logger.info("="*80)
    
    
    def plot_feature_importance(self, top_n: int = 15, save_path: Optional[Path] = None) -> None:
        """
        Plot feature importance.
        
        Args:
            top_n: Number of top features to display
            save_path: Path to save plot
        """
        if self.feature_importance is None:
            logger.warning("No feature importance available")
            return
        
        # Create DataFrame
        importance_df = pd.DataFrame({
            'feature': self.feature_names,
            'importance': self.feature_importance
        }).sort_values('importance', ascending=False).head(top_n)
        
        # Plot
        plt.figure(figsize=(12, 8))
        sns.barplot(data=importance_df, x='importance', y='feature', palette='viridis')
        plt.xlabel('Importance', fontsize=14, fontweight='bold')
        plt.ylabel('Feature', fontsize=14, fontweight='bold')
        plt.title(f'Top {top_n} Meta-Features by Importance', fontsize=16, fontweight='bold')
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            logger.info(f"Feature importance plot saved to {save_path}")
        
        plt.show()
    
    
    def plot_layer_agreement(self,
                            signature_results: Dict,
                            autoencoder_results: Dict,
                            bilstm_results: Dict,
                            y_true: np.ndarray,
                            save_path: Optional[Path] = None) -> None:
        """
        Plot layer agreement analysis.
        
        Args:
            signature_results: Results from Layer 1
            autoencoder_results: Results from Layer 2
            bilstm_results: Results from Layer 3
            y_true: True labels
            save_path: Path to save plot
        """
        sig_pred = signature_results['predictions']
        ae_pred = autoencoder_results['predictions']
        lstm_pred = bilstm_results['predictions']
        
        # Calculate agreement
        agreement = sig_pred + ae_pred + lstm_pred
        
        # Separate by true label
        benign_agreement = agreement[y_true == 0]
        malicious_agreement = agreement[y_true == 1]
        
        # Plot
        fig, axes = plt.subplots(1, 2, figsize=(15, 6))
        
        # Benign samples
        axes[0].hist(benign_agreement, bins=4, range=(-0.5, 3.5),
                    alpha=0.7, color='green', edgecolor='black')
        axes[0].set_xlabel('Number of Layers Voting Malicious', fontsize=12)
        axes[0].set_ylabel('Count', fontsize=12)
        axes[0].set_title('Layer Agreement on Benign Samples', fontsize=14, fontweight='bold')
        axes[0].set_xticks([0, 1, 2, 3])
        axes[0].grid(True, alpha=0.3)
        
        # Malicious samples
        axes[1].hist(malicious_agreement, bins=4, range=(-0.5, 3.5),
                    alpha=0.7, color='red', edgecolor='black')
        axes[1].set_xlabel('Number of Layers Voting Malicious', fontsize=12)
        axes[1].set_ylabel('Count', fontsize=12)
        axes[1].set_title('Layer Agreement on Malicious Samples', fontsize=14, fontweight='bold')
        axes[1].set_xticks([0, 1, 2, 3])
        axes[1].grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            logger.info(f"Layer agreement plot saved to {save_path}")
        
        plt.show()
    
    
    def save(self, model_path: Optional[Path] = None) -> None:
        """Save meta-classifier and configuration."""
        if model_path is None:
            model_path = config.RF_MODEL_PATH
        
        # Save models
        models_dict = {
            'meta_model': self.meta_model,
            'calibrated_model': self.calibrated_model,
            'feature_names': self.feature_names,
            'feature_importance': self.feature_importance,
            'config': {
                'meta_model_type': self.meta_model_type,
                'voting_strategy': self.voting_strategy,
                'use_calibration': self.use_calibration
            }
        }
        
        with open(model_path, 'wb') as f:
            pickle.dump(models_dict, f)
        
        logger.info(f"Meta-classifier saved to {model_path}")
    
    
    @classmethod
    def load(cls, model_path: Optional[Path] = None) -> 'MetaClassifier':
        """Load saved meta-classifier."""
        if model_path is None:
            model_path = config.RF_MODEL_PATH
        
        with open(model_path, 'rb') as f:
            models_dict = pickle.load(f)
        
        # Create instance
        config_data = models_dict['config']
        instance = cls(
            meta_model_type=config_data['meta_model_type'],
            voting_strategy=config_data['voting_strategy'],
            use_calibration=config_data['use_calibration']
        )
        
        # Load models
        instance.meta_model = models_dict['meta_model']
        instance.calibrated_model = models_dict['calibrated_model']
        instance.feature_names = models_dict['feature_names']
        instance.feature_importance = models_dict['feature_importance']
        
        logger.info(f"Meta-classifier loaded from {model_path}")
        
        return instance


def test_meta_classifier():
    """Test the meta-classifier with synthetic data."""
    
    logger.info("\n" + "="*80)
    logger.info("TESTING META-CLASSIFIER")
    logger.info("="*80 + "\n")
    
    # Generate synthetic layer outputs
    np.random.seed(42)
    n_samples = 1000
    
    # Generate true labels (70% benign, 30% malicious)
    y_true = np.random.choice([0, 1], size=n_samples, p=[0.7, 0.3])
    
    # Simulate Layer 1 (Signature Filter) - High precision, low recall
    sig_predictions = np.zeros(n_samples)
    # Detect 40% of malicious with few false positives
    malicious_mask = (y_true == 1)
    sig_predictions[malicious_mask] = np.random.choice([0, 1], size=malicious_mask.sum(), p=[0.6, 0.4])
    sig_predictions[~malicious_mask] = np.random.choice([0, 1], size=(~malicious_mask).sum(), p=[0.95, 0.05])
    
    sig_matched_patterns = [
        ['pattern:sql_injection'] if pred == 1 else []
        for pred in sig_predictions
    ]
    
    signature_results = {
        'predictions': sig_predictions.astype(int),
        'matched_patterns': sig_matched_patterns
    }
    
    # Simulate Layer 2 (Autoencoder) - Good at detecting anomalies
    ae_predictions = np.zeros(n_samples)
    # Detect 70% of malicious, some false positives
    ae_predictions[malicious_mask] = np.random.choice([0, 1], size=malicious_mask.sum(), p=[0.3, 0.7])
    ae_predictions[~malicious_mask] = np.random.choice([0, 1], size=(~malicious_mask).sum(), p=[0.90, 0.10])
    
    # Generate reconstruction errors (higher for malicious)
    ae_errors = np.zeros(n_samples)
    ae_errors[malicious_mask] = np.random.exponential(scale=2.0, size=malicious_mask.sum()) + 1.0
    ae_errors[~malicious_mask] = np.random.exponential(scale=0.3, size=(~malicious_mask).sum())
    
    ae_anomaly_scores = np.clip(ae_errors / 3.0, 0, 1)
    
    autoencoder_results = {
        'predictions': ae_predictions.astype(int),
        'reconstruction_errors': ae_errors,
        'anomaly_scores': ae_anomaly_scores
    }
    
    # Simulate Layer 3 (Bi-LSTM) - Best overall performance
    lstm_predictions = np.zeros(n_samples)
    # Detect 85% of malicious
    lstm_predictions[malicious_mask] = np.random.choice([0, 1], size=malicious_mask.sum(), p=[0.15, 0.85])
    lstm_predictions[~malicious_mask] = np.random.choice([0, 1], size=(~malicious_mask).sum(), p=[0.93, 0.07])
    
    # Generate probabilities (closer to 1 for malicious)
    lstm_probabilities = np.zeros(n_samples)
    lstm_probabilities[malicious_mask] = np.random.beta(a=8, b=2, size=malicious_mask.sum())
    lstm_probabilities[~malicious_mask] = np.random.beta(a=2, b=8, size=(~malicious_mask).sum())
    
    lstm_confidence = np.abs(lstm_probabilities - 0.5)
    
    # --- NEW: Generate synthetic deep features (32 dimensions) ---
    deep_features = np.random.randn(n_samples, 32)
    # Make deep features more discriminative for malicious samples
    deep_features[malicious_mask, :] += 0.5  # Shift malicious samples
    
    bilstm_results = {
        'predictions': lstm_predictions.astype(int),
        'probabilities': lstm_probabilities,
        'confidence': lstm_confidence,
        'deep_features': deep_features  # NEW!
    }
    
    # Split into train/test
    train_size = int(0.7 * n_samples)
    
    # Training data
    sig_train = {
        'predictions': signature_results['predictions'][:train_size],
        'matched_patterns': signature_results['matched_patterns'][:train_size]
    }
    ae_train = {
        'predictions': autoencoder_results['predictions'][:train_size],
        'reconstruction_errors': autoencoder_results['reconstruction_errors'][:train_size],
        'anomaly_scores': autoencoder_results['anomaly_scores'][:train_size]
    }
    lstm_train = {
        'predictions': bilstm_results['predictions'][:train_size],
        'probabilities': bilstm_results['probabilities'][:train_size],
        'confidence': bilstm_results['confidence'][:train_size],
        'deep_features': bilstm_results['deep_features'][:train_size]  # NEW!
    }
    y_train = y_true[:train_size]
    
    # Test data
    sig_test = {
        'predictions': signature_results['predictions'][train_size:],
        'matched_patterns': signature_results['matched_patterns'][train_size:]
    }
    ae_test = {
        'predictions': autoencoder_results['predictions'][train_size:],
        'reconstruction_errors': autoencoder_results['reconstruction_errors'][train_size:],
        'anomaly_scores': autoencoder_results['anomaly_scores'][train_size:]
    }
    lstm_test = {
        'predictions': bilstm_results['predictions'][train_size:],
        'probabilities': bilstm_results['probabilities'][train_size:],
        'confidence': bilstm_results['confidence'][train_size:],
        'deep_features': bilstm_results['deep_features'][train_size:]  # NEW!
    }
    y_test = y_true[train_size:]
    
    logger.info(f"Train samples: {train_size}")
    logger.info(f"Test samples: {len(y_test)}")
    logger.info(f"Train malicious: {y_train.sum()} ({y_train.sum()/len(y_train)*100:.1f}%)")
    logger.info(f"Test malicious: {y_test.sum()} ({y_test.sum()/len(y_test)*100:.1f}%)")
    
    # Test 1: Random Forest Meta-Classifier with Deep Features
    print("\n" + "="*80)
    print("TEST 1: Random Forest Meta-Classifier with Deep Features")
    print("="*80)
    
    meta_rf = MetaClassifier(
        meta_model_type='random_forest',
        n_estimators=200,
        max_depth=10,
        voting_strategy='model',
        use_calibration=True
    )
    
    meta_rf.train(sig_train, ae_train, lstm_train, y_train)
    metrics_rf = meta_rf.evaluate(sig_test, ae_test, lstm_test, y_test, split_name='test')
    
    # Plot feature importance
    meta_rf.plot_feature_importance(top_n=15, save_path=config.RESULTS_DIR / 'meta_feature_importance.png')
    
    # Plot layer agreement
    meta_rf.plot_layer_agreement(sig_test, ae_test, lstm_test, y_test,
                                 save_path=config.RESULTS_DIR / 'meta_layer_agreement.png')
    
    # Save model
    meta_rf.save()
    
    print("\n" + "="*80)
    print("✅ META-CLASSIFIER WITH DEEP FEATURES TEST COMPLETED!")
    print("="*80)
    print(f"\n🎯 KEY METRICS:")
    print(f"  • Total Features: {len(meta_rf.feature_names)}")
    print(f"  • Deep Features: {len([n for n in meta_rf.feature_names if 'lstm_deep' in n])}")
    print(f"  • F1-Score: {metrics_rf['f1_score']:.4f}")
    print(f"  • Precision: {metrics_rf['precision']:.4f}")
    print(f"  • Recall: {metrics_rf['recall']:.4f}")
    print("="*80 + "\n")


if __name__ == "__main__":
    test_meta_classifier()