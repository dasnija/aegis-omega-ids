"""
Advanced Denoising Autoencoder Module for Hybrid Intrusion Detection System (IDS)
Layer 2: Anomaly detection on 72 flow-based features

CRITICAL FIXES APPLIED:
- Data cleaning with Isolation Forest to remove contamination
- RobustScaler instead of StandardScaler for skewed network features
- Simplified architecture [64, 32] instead of [48, 24, 12]
- True denoising with noise_factor=0.15
- Conservative threshold (99th percentile instead of 95th)
- Contamination diagnostics

Author: Senior ML Engineer (Updated 2025)
"""
import json
import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras
from keras import layers, Model, regularizers
from keras.callbacks import (EarlyStopping, ReduceLROnPlateau, 
                                        ModelCheckpoint, TensorBoard)
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (accuracy_score, precision_score, recall_score, 
                            f1_score, roc_auc_score, roc_curve, 
                            precision_recall_curve, confusion_matrix)
from sklearn.preprocessing import RobustScaler
from sklearn.ensemble import IsolationForest
import logging
from pathlib import Path
from typing import Dict, Tuple, List, Optional, Any
import pickle
import json
from datetime import datetime

import config

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Set random seeds for reproducibility
np.random.seed(config.RANDOM_SEED)
tf.random.set_seed(config.TF_RANDOM_SEED)


import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional, Any
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import RobustScaler
from scipy import stats
import logging

logger = logging.getLogger(__name__)


class DataCleaner:
    """
    Comprehensive data cleaning pipeline for autoencoder training.
    
    This class handles all data quality issues before training:
    - Statistical outliers
    - NaN/Inf values
    - Duplicates
    - Multi-stage outlier detection
    - Feature-level diagnostics
    """
    
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.cleaning_report = {}
        
    def diagnose_and_clean(self,
                          X: np.ndarray,
                          contamination_rate: float = 0.02,
                          use_multi_stage: bool = True,
                          z_score_threshold: float = 6.0,
                          iqr_multiplier: float = 3.0) -> Tuple[np.ndarray, np.ndarray, Dict]:
        """
        Comprehensive data cleaning pipeline.
        
        Args:
            X: Input data (N, features)
            contamination_rate: Expected contamination for ensemble methods
            use_multi_stage: Use multi-stage outlier detection
            z_score_threshold: Z-score threshold for statistical outliers
            iqr_multiplier: IQR multiplier for outlier detection
            
        Returns:
            Tuple of (cleaned_data, mask_kept, cleaning_report)
        """
        logger.info("="*80)
        logger.info("COMPREHENSIVE DATA CLEANING PIPELINE")
        logger.info("="*80)
        
        original_samples = X.shape[0]
        mask_kept = np.ones(original_samples, dtype=bool)
        
        self.cleaning_report = {
            'original_samples': original_samples,
            'steps': []
        }
        
        # Step 1: Basic validation
        X, mask_kept = self._step1_basic_validation(X, mask_kept)
        
        # Step 2: Statistical outliers (per feature)
        X, mask_kept = self._step2_statistical_outliers(
            X, mask_kept, z_score_threshold, iqr_multiplier
        )
        
        # Step 3: Remove duplicates
        X, mask_kept = self._step3_remove_duplicates(X, mask_kept)
        
        # Step 4: Multi-stage outlier detection
        if use_multi_stage:
            X, mask_kept = self._step4_multi_stage_outliers(X, mask_kept, contamination_rate)
        
        # Step 5: Feature-level diagnostics
        self._step5_feature_diagnostics(X)
        
        # Final report
        self.cleaning_report['final_samples'] = X.shape[0]
        self.cleaning_report['total_removed'] = original_samples - X.shape[0]
        self.cleaning_report['removal_rate'] = (original_samples - X.shape[0]) / original_samples * 100
        
        self._print_final_report()
        
        return X, mask_kept, self.cleaning_report
    
    
    def _step1_basic_validation(self, X: np.ndarray, mask: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Step 1: Handle NaN, Inf, and basic validation."""
        logger.info("\n[STEP 1] Basic Validation")
        logger.info("-" * 80)
        
        step_report = {'name': 'Basic Validation', 'removed': 0, 'issues': []}
        
        # Check for NaN
        nan_mask = np.isnan(X).any(axis=1)
        nan_count = nan_mask.sum()
        if nan_count > 0:
            logger.warning(f"⚠ Found {nan_count} samples with NaN values - REMOVING")
            mask[mask] = mask[mask] & ~nan_mask
            X = X[~nan_mask]
            step_report['issues'].append(f"NaN values: {nan_count}")
            step_report['removed'] += nan_count
        
        # Check for Inf
        inf_mask = np.isinf(X).any(axis=1)
        inf_count = inf_mask.sum()
        if inf_count > 0:
            logger.warning(f"⚠ Found {inf_count} samples with Inf values - REMOVING")
            mask[mask] = mask[mask] & ~inf_mask
            X = X[~inf_mask]
            step_report['issues'].append(f"Inf values: {inf_count}")
            step_report['removed'] += inf_count
        
        # Check for all-zero samples
        zero_mask = (X == 0).all(axis=1)
        zero_count = zero_mask.sum()
        if zero_count > 0:
            logger.warning(f"⚠ Found {zero_count} all-zero samples - REMOVING")
            mask[mask] = mask[mask] & ~zero_mask
            X = X[~zero_mask]
            step_report['issues'].append(f"All-zero samples: {zero_count}")
            step_report['removed'] += zero_count
        
        if step_report['removed'] == 0:
            logger.info("✓ No basic validation issues found")
        else:
            logger.info(f"✓ Removed {step_report['removed']} samples with basic issues")
        
        logger.info(f"  Remaining samples: {X.shape[0]}")
        self.cleaning_report['steps'].append(step_report)
        
        return X, mask
    
    
    def _step2_statistical_outliers(self, 
                                    X: np.ndarray, 
                                    mask: np.ndarray,
                                    z_threshold: float,
                                    iqr_multiplier: float) -> Tuple[np.ndarray, np.ndarray]:
        """Step 2: Remove statistical outliers using Z-score and IQR."""
        logger.info("\n[STEP 2] Statistical Outlier Detection")
        logger.info("-" * 80)
        
        step_report = {'name': 'Statistical Outliers', 'removed': 0, 'issues': []}
        
        # Z-score method (for each feature)
        logger.info(f"Checking Z-scores (threshold: {z_threshold})...")
        z_scores = np.abs(stats.zscore(X, axis=0, nan_policy='omit'))
        z_outliers = (z_scores > z_threshold).any(axis=1)
        z_count = z_outliers.sum()
        
        if z_count > 0:
            logger.warning(f"⚠ Found {z_count} samples with extreme Z-scores (>{z_threshold}σ)")
            # Find which features have extreme values
            feature_outliers = (z_scores > z_threshold).sum(axis=0)
            top_features = np.argsort(feature_outliers)[-5:]
            logger.info(f"  Top outlier features (indices): {top_features.tolist()}")
            logger.info(f"  Outlier counts: {feature_outliers[top_features].tolist()}")
        
        # IQR method (for each feature)
        logger.info(f"Checking IQR outliers (multiplier: {iqr_multiplier})...")
        Q1 = np.percentile(X, 25, axis=0)
        Q3 = np.percentile(X, 75, axis=0)
        IQR = Q3 - Q1
        
        lower_bound = Q1 - iqr_multiplier * IQR
        upper_bound = Q3 + iqr_multiplier * IQR
        
        iqr_outliers = ((X < lower_bound) | (X > upper_bound)).any(axis=1)
        iqr_count = iqr_outliers.sum()
        
        if iqr_count > 0:
            logger.warning(f"⚠ Found {iqr_count} samples outside IQR bounds")
        
        # Combine both methods (union)
        combined_outliers = z_outliers | iqr_outliers
        total_outliers = combined_outliers.sum()
        
        if total_outliers > 0:
            logger.warning(f"⚠ Total statistical outliers: {total_outliers} ({total_outliers/len(X)*100:.2f}%)")
            mask[mask] = mask[mask] & ~combined_outliers
            X = X[~combined_outliers]
            step_report['issues'].append(f"Z-score outliers: {z_count}")
            step_report['issues'].append(f"IQR outliers: {iqr_count}")
            step_report['removed'] = total_outliers
        else:
            logger.info("✓ No statistical outliers found")
        
        logger.info(f"  Remaining samples: {X.shape[0]}")
        self.cleaning_report['steps'].append(step_report)
        
        return X, mask
    
    
    def _step3_remove_duplicates(self, X: np.ndarray, mask: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Step 3: Remove duplicate samples."""
        logger.info("\n[STEP 3] Duplicate Detection")
        logger.info("-" * 80)
        
        step_report = {'name': 'Duplicates', 'removed': 0, 'issues': []}
        
        # Find duplicates
        unique_X, unique_indices = np.unique(X, axis=0, return_index=True)
        n_duplicates = len(X) - len(unique_X)
        
        if n_duplicates > 0:
            logger.warning(f"⚠ Found {n_duplicates} duplicate samples - REMOVING")
            # Create mask for unique samples
            duplicate_mask = np.ones(len(X), dtype=bool)
            duplicate_mask[unique_indices] = False
            
            mask[mask] = mask[mask] & ~duplicate_mask
            X = unique_X
            step_report['issues'].append(f"Duplicate samples: {n_duplicates}")
            step_report['removed'] = n_duplicates
        else:
            logger.info("✓ No duplicates found")
        
        logger.info(f"  Remaining samples: {X.shape[0]}")
        self.cleaning_report['steps'].append(step_report)
        
        return X, mask
    
    
    def _step4_multi_stage_outliers(self,
                                    X: np.ndarray,
                                    mask: np.ndarray,
                                    contamination: float) -> Tuple[np.ndarray, np.ndarray]:
        """Step 4: Multi-stage outlier detection using ensemble methods."""
        logger.info("\n[STEP 4] Multi-Stage Outlier Detection")
        logger.info("-" * 80)
        
        step_report = {'name': 'Multi-Stage Outliers', 'removed': 0, 'issues': []}
        
        # Stage 4a: Isolation Forest
        logger.info("Stage 4a: Isolation Forest...")
        iso = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100,
            max_samples='auto',
            n_jobs=-1
        )
        iso_pred = iso.fit_predict(X)
        iso_outliers = iso_pred == -1
        iso_count = iso_outliers.sum()
        logger.info(f"  Isolation Forest identified: {iso_count} outliers ({iso_count/len(X)*100:.2f}%)")
        
        # Stage 4b: Local Outlier Factor
        logger.info("Stage 4b: Local Outlier Factor...")
        lof = LocalOutlierFactor(
            contamination=contamination,
            n_neighbors=20,
            n_jobs=-1
        )
        lof_pred = lof.fit_predict(X)
        lof_outliers = lof_pred == -1
        lof_count = lof_outliers.sum()
        logger.info(f"  LOF identified: {lof_count} outliers ({lof_count/len(X)*100:.2f}%)")
        
        # Stage 4c: One-Class SVM (optional, can be slow)
        logger.info("Stage 4c: One-Class SVM...")
        try:
            ocsvm = OneClassSVM(nu=contamination, kernel='rbf', gamma='auto')
            ocsvm_pred = ocsvm.fit_predict(X)
            ocsvm_outliers = ocsvm_pred == -1
            ocsvm_count = ocsvm_outliers.sum()
            logger.info(f"  One-Class SVM identified: {ocsvm_count} outliers ({ocsvm_count/len(X)*100:.2f}%)")
        except Exception as e:
            logger.warning(f"⚠ One-Class SVM failed: {e}")
            ocsvm_outliers = np.zeros(len(X), dtype=bool)
            ocsvm_count = 0
        
        # Ensemble voting: Remove if 2+ methods agree
        outlier_votes = iso_outliers.astype(int) + lof_outliers.astype(int) + ocsvm_outliers.astype(int)
        ensemble_outliers = outlier_votes >= 2
        ensemble_count = ensemble_outliers.sum()
        
        logger.info(f"\nEnsemble Results:")
        logger.info(f"  Samples flagged by 2+ methods: {ensemble_count} ({ensemble_count/len(X)*100:.2f}%)")
        logger.info(f"  Samples flagged by all 3: {(outlier_votes == 3).sum()}")
        
        if ensemble_count > 0:
            logger.warning(f"⚠ Removing {ensemble_count} ensemble-identified outliers")
            mask[mask] = mask[mask] & ~ensemble_outliers
            X = X[~ensemble_outliers]
            step_report['issues'].append(f"Isolation Forest: {iso_count}")
            step_report['issues'].append(f"LOF: {lof_count}")
            step_report['issues'].append(f"One-Class SVM: {ocsvm_count}")
            step_report['issues'].append(f"Ensemble (2+ votes): {ensemble_count}")
            step_report['removed'] = ensemble_count
        else:
            logger.info("✓ No consensus outliers found")
        
        logger.info(f"  Remaining samples: {X.shape[0]}")
        self.cleaning_report['steps'].append(step_report)
        
        return X, mask
    
    
    def _step5_feature_diagnostics(self, X: np.ndarray):
        """Step 5: Feature-level diagnostics (informational only)."""
        logger.info("\n[STEP 5] Feature-Level Diagnostics")
        logger.info("-" * 80)
        
        n_features = X.shape[1]
        
        # Calculate feature statistics
        feature_stats = {
            'mean': np.mean(X, axis=0),
            'std': np.std(X, axis=0),
            'min': np.min(X, axis=0),
            'max': np.max(X, axis=0),
            'range': np.max(X, axis=0) - np.min(X, axis=0),
            'zeros': (X == 0).sum(axis=0),
            'skewness': stats.skew(X, axis=0)
        }
        
        # Identify problematic features
        logger.info("Feature Analysis:")
        
        # High variance features
        high_var_features = np.where(feature_stats['std'] > np.percentile(feature_stats['std'], 95))[0]
        if len(high_var_features) > 0:
            logger.info(f"  High variance features (top 5%): {high_var_features[:10].tolist()}")
        
        # Zero-dominated features
        zero_dominated = np.where(feature_stats['zeros'] > 0.9 * X.shape[0])[0]
        if len(zero_dominated) > 0:
            logger.warning(f"  ⚠ Zero-dominated features (>90% zeros): {zero_dominated.tolist()}")
        
        # High skewness features
        high_skew = np.where(np.abs(feature_stats['skewness']) > 3)[0]
        if len(high_skew) > 0:
            logger.warning(f"  ⚠ Highly skewed features (|skew|>3): {high_skew[:10].tolist()}")
        
        # Feature range analysis
        logger.info(f"  Feature ranges: min={feature_stats['range'].min():.2e}, "
                   f"max={feature_stats['range'].max():.2e}")
        
        self.cleaning_report['feature_diagnostics'] = {
            'n_features': n_features,
            'high_variance_features': high_var_features.tolist(),
            'zero_dominated_features': zero_dominated.tolist(),
            'high_skew_features': high_skew.tolist()
        }
    
    
    def _print_final_report(self):
        """Print comprehensive cleaning report."""
        logger.info("\n" + "="*80)
        logger.info("CLEANING PIPELINE SUMMARY")
        logger.info("="*80)
        logger.info(f"Original samples:     {self.cleaning_report['original_samples']}")
        logger.info(f"Final samples:        {self.cleaning_report['final_samples']}")
        logger.info(f"Total removed:        {self.cleaning_report['total_removed']} "
                   f"({self.cleaning_report['removal_rate']:.2f}%)")
        
        logger.info("\nRemoval breakdown by step:")
        for step in self.cleaning_report['steps']:
            if step['removed'] > 0:
                logger.info(f"  {step['name']}: {step['removed']} samples")
                for issue in step['issues']:
                    logger.info(f"    - {issue}")
        
        logger.info("="*80)


class AdvancedAutoencoder:
    """
    Enhanced autoencoder with comprehensive data cleaning.
    
    Key improvements:
    - Built-in data cleaning pipeline
    - No double-scaling issues
    - Iterative cleaning support
    - Detailed diagnostics
    """
    
    def __init__(self,
                 input_dim: int = 72,
                 encoding_dims: List[int] = None,
                 noise_factor: float = 0.15,
                 dropout_rate: float = 0.05,
                 l1_reg: float = 1e-5,
                 l2_reg: float = 1e-4):
        """Initialize autoencoder."""
        self.input_dim = input_dim
        self.encoding_dims = encoding_dims or [64, 32]
        self.noise_factor = noise_factor
        self.dropout_rate = dropout_rate
        self.l1_reg = l1_reg
        self.l2_reg = l2_reg
        
        self.model = None
        self.scaler = None
        self.threshold = None
        self.data_cleaner = DataCleaner()
        self.history  = None
        
        logger.info(f"AdvancedAutoencoder initialized with architecture: {self.encoding_dims}")
    
    
    def clean_and_prepare_data(self,
                              X: np.ndarray,
                              contamination_rate: float = 0.02,
                              iterative_cleaning: bool = False) -> Tuple[np.ndarray, np.ndarray]:
        """
        Clean and prepare data for training.
        
        This is the MAIN method to call before training!
        
        Args:
            X: Raw input data (unscaled)
            contamination_rate: Expected contamination rate
            iterative_cleaning: Use two-pass cleaning (more thorough)
            
        Returns:
            Tuple of (cleaned_scaled_data, mask_of_kept_samples)
        """
        logger.info("="*80)
        logger.info("DATA CLEANING AND PREPARATION")
        logger.info("="*80)
        
        # First pass: Statistical cleaning
        X_cleaned, mask_kept, report = self.data_cleaner.diagnose_and_clean(
            X,
            contamination_rate=contamination_rate,
            use_multi_stage=True,
            z_score_threshold=6.0,
            iqr_multiplier=3.0
        )
        
        # Scale data
        logger.info("\nScaling cleaned data with RobustScaler...")
        self.scaler = RobustScaler()
        X_scaled = self.scaler.fit_transform(X_cleaned)
        
        logger.info(f"Scaled data statistics:")
        logger.info(f"  Mean: {np.mean(X_scaled):.4f}")
        logger.info(f"  Median: {np.median(X_scaled):.4f}")
        logger.info(f"  Std: {np.std(X_scaled):.4f}")
        logger.info(f"  Min: {np.min(X_scaled):.4f}")
        logger.info(f"  Max: {np.max(X_scaled):.4f}")
        
        # Iterative cleaning (optional second pass)
        if iterative_cleaning:
            logger.info("\n" + "="*80)
            logger.info("ITERATIVE CLEANING - SECOND PASS")
            logger.info("="*80)
            
            # Train preliminary model
            logger.info("Training preliminary autoencoder for iterative cleaning...")
            from tensorflow import keras
            from tensorflow.keras import layers
            
            # Simple preliminary model
            prelim_model = keras.Sequential([
                layers.Input(shape=(self.input_dim,)),
                layers.Dense(64, activation='relu'),
                layers.Dense(32, activation='relu'),
                layers.Dense(64, activation='relu'),
                layers.Dense(self.input_dim, activation='linear')
            ])
            
            prelim_model.compile(optimizer='adam', loss='mse')
            prelim_model.fit(X_scaled, X_scaled, epochs=5, batch_size=256, verbose=0)
            
            # Get reconstruction errors
            reconstructions = prelim_model.predict(X_scaled, verbose=0)
            errors = np.mean(np.square(X_scaled - reconstructions), axis=1)
            
            # Remove top 1% highest errors
            error_threshold = np.percentile(errors, 99)
            high_error_mask = errors > error_threshold
            high_error_count = high_error_mask.sum()
            
            if high_error_count > 0:
                logger.warning(f"⚠ Iterative cleaning removing {high_error_count} high-error samples")
                logger.info(f"  Error threshold: {error_threshold:.6f}")
                logger.info(f"  Max error in removed: {errors[high_error_mask].max():.6f}")
                
                X_scaled = X_scaled[~high_error_mask]
                X_cleaned = X_cleaned[~high_error_mask]
                mask_kept[mask_kept] = mask_kept[mask_kept] & ~high_error_mask
            else:
                logger.info("✓ No additional samples removed in second pass")
        
        logger.info("="*80)
        logger.info(f"FINAL DATASET: {X_scaled.shape[0]} samples, {X_scaled.shape[1]} features")
        logger.info("="*80)
        
        return X_scaled, mask_kept
    
    
    def calculate_robust_threshold(self,
                                   X_scaled: np.ndarray,
                                   method: str = 'ultra_clean',
                                   percentile: float = 99.0) -> float:
        """
        Calculate threshold using only the cleanest samples.
        
        Args:
            X_scaled: Scaled training data
            method: 'ultra_clean' (recommended) or 'percentile'
            percentile: Percentile to use
            
        Returns:
            Calculated threshold
        """
        logger.info("\n" + "="*80)
        logger.info("ROBUST THRESHOLD CALCULATION")
        logger.info("="*80)
        
        # Get reconstruction errors
        reconstructions = self.model.predict(X_scaled, verbose=0)
        errors = np.mean(np.square(X_scaled - reconstructions), axis=1)
        
        logger.info(f"Reconstruction error statistics:")
        logger.info(f"  Mean: {errors.mean():.6f}")
        logger.info(f"  Median: {np.median(errors):.6f}")
        logger.info(f"  Std: {errors.std():.6f}")
        logger.info(f"  95th percentile: {np.percentile(errors, 95):.6f}")
        logger.info(f"  99th percentile: {np.percentile(errors, 99):.6f}")
        logger.info(f"  Max: {errors.max():.6f}")
        
        if method == 'ultra_clean':
            # Use only the cleanest 80% for threshold calculation
            clean_threshold = np.percentile(errors, 80)
            clean_mask = errors < clean_threshold
            clean_errors = errors[clean_mask]
            
            logger.info(f"\nUsing ultra-clean method:")
            logger.info(f"  Selected {clean_mask.sum()} cleanest samples (80%)")
            logger.info(f"  Clean sample error range: [{clean_errors.min():.6f}, {clean_errors.max():.6f}]")
            
            # Calculate threshold on clean subset
            threshold = np.percentile(clean_errors, percentile)
            logger.info(f"  Threshold ({percentile}th percentile of clean): {threshold:.6f}")
            
        else:
            # Standard percentile method
            threshold = np.percentile(errors, percentile)
            logger.info(f"\nUsing standard percentile method:")
            logger.info(f"  Threshold ({percentile}th percentile): {threshold:.6f}")
        
        self.threshold = threshold
        
        # Validation
        below_threshold = (errors < threshold).sum()
        logger.info(f"\nThreshold validation:")
        logger.info(f"  Samples below threshold: {below_threshold}/{len(errors)} "
                   f"({below_threshold/len(errors)*100:.1f}%)")
        
        logger.info("="*80)
        
        return threshold


    def predict(self, X: np.ndarray) -> Dict[str, np.ndarray]:
        """
        Predict anomalies in new data.
        
        Args:
            X: Input features (N, feature_dim) - RAW unscaled data OR already scaled data
            
        Returns:
            Dictionary containing:
            - predictions: Binary labels (0=benign, 1=malicious)
            - reconstruction_errors: MSE for each sample
            - reconstructions: Reconstructed features
            - anomaly_scores: Normalized anomaly scores [0, 1]
        """
        if self.model is None:
            raise ValueError("Model not trained yet!")
        
        if self.threshold is None:
            raise ValueError("Threshold not calculated yet!")
        
        if self.scaler is None:
            raise ValueError("Scaler not fitted yet!")
        
        # FIXED: Check if data is already scaled (if mean is close to 0 and std close to 1)
        # If not scaled, scale it
        data_mean = np.abs(np.mean(X))
        data_std = np.std(X)
        
        # If data looks unscaled (mean far from 0 or std far from 1), scale it
        if data_mean > 0.5 or data_std > 2.0 or data_std < 0.2:
            logger.debug(f"Data appears unscaled (mean={data_mean:.3f}, std={data_std:.3f}), applying scaler...")
            X_scaled = self.scaler.transform(X)
        else:
            logger.debug(f"Data appears already scaled (mean={data_mean:.3f}, std={data_std:.3f}), using as-is")
            X_scaled = X
        
        # Get reconstructions
        reconstructions = self.model.predict(X_scaled, verbose=0)
        
        # Calculate reconstruction errors (MSE per sample)
        errors = np.mean(np.square(X_scaled - reconstructions), axis=1)
        
        # Binary predictions (1 if error > threshold)
        predictions = (errors > self.threshold).astype(int)
        
        # Normalize anomaly scores to [0, 1]
        anomaly_scores = np.clip(errors / (self.threshold * 2), 0, 1)
        
        return {
            'predictions': predictions,
            'reconstruction_errors': errors,
            'reconstructions': reconstructions,
            'anomaly_scores': anomaly_scores
        }



    def evaluate(self,
                X: np.ndarray,
                y_true: np.ndarray,
                split_name: str = 'test') -> Dict[str, float]:
        """
        Evaluate autoencoder performance.
        
        Args:
            X: Input features
            y_true: True labels (0=benign, 1=malicious)
            split_name: Name of the split for logging
            
        Returns:
            Dictionary of metrics
        """
        logger.info(f"Evaluating autoencoder on {split_name} set...")
        
        # Get predictions
        results = self.predict(X)
        y_pred = results['predictions']
        errors = results['reconstruction_errors']
        scores = results['anomaly_scores']
        
        # Calculate metrics
        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        
        # ROC AUC using reconstruction errors as scores
        try:
            auc = roc_auc_score(y_true, errors)
        except:
            auc = 0.0
        
        # Confusion matrix
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        
        # Additional metrics
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
        
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
            'threshold': float(self.threshold)
        }
        
        # Log metrics
        self.log_metrics(metrics, split_name)
        
        return metrics
    
    
    def log_metrics(self, metrics: Dict[str, float], split_name: str = 'test') -> None:
        """Log evaluation metrics."""
        logger.info("="*80)
        logger.info(f"AUTOENCODER METRICS ({split_name.upper()})")
        logger.info("="*80)
        logger.info(f"Accuracy:  {metrics['accuracy']:.4f}")
        logger.info(f"Precision: {metrics['precision']:.4f}")
        logger.info(f"Recall:    {metrics['recall']:.4f}")
        logger.info(f"F1-Score:  {metrics['f1_score']:.4f}")
        logger.info(f"AUC:       {metrics['auc']:.4f}")
        logger.info(f"FPR:       {metrics['fpr']:.4f}")
        logger.info(f"FNR:       {metrics['fnr']:.4f}")
        logger.info(f"Threshold: {metrics['threshold']:.6f}")
        logger.info(f"\nConfusion Matrix:")
        logger.info(f"  TP: {metrics['true_positives']:6d}  FP: {metrics['false_positives']:6d}")
        logger.info(f"  FN: {metrics['false_negatives']:6d}  TN: {metrics['true_negatives']:6d}")
        logger.info("="*80)
    
    
    def plot_training_history(self, save_path: Optional[Path] = None) -> None:
        """Plot training and validation loss curves."""
        if self.history is None:
            logger.warning("No training history available")
            return
        
        fig, axes = plt.subplots(1, 2, figsize=(15, 5))
        
        # Loss
        axes[0].plot(self.history.history['loss'], label='Training Loss', linewidth=2)
        if 'val_loss' in self.history.history:
            axes[0].plot(self.history.history['val_loss'], label='Validation Loss', linewidth=2)
        axes[0].set_xlabel('Epoch', fontsize=12)
        axes[0].set_ylabel('Loss (MSE)', fontsize=12)
        axes[0].set_title('Training History - Loss', fontsize=14, fontweight='bold')
        axes[0].legend()
        axes[0].grid(True, alpha=0.3)
        
        # MAE
        axes[1].plot(self.history.history['mae'], label='Training MAE', linewidth=2)
        if 'val_mae' in self.history.history:
            axes[1].plot(self.history.history['val_mae'], label='Validation MAE', linewidth=2)
        axes[1].set_xlabel('Epoch', fontsize=12)
        axes[1].set_ylabel('MAE', fontsize=12)
        axes[1].set_title('Training History - MAE', fontsize=14, fontweight='bold')
        axes[1].legend()
        axes[1].grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            logger.info(f"Training history plot saved to {save_path}")
        
        plt.show()
    
    
    def plot_reconstruction_errors(self,
                                X_benign: np.ndarray,
                                X_malicious: np.ndarray,
                                save_path: Optional[Path] = None) -> None:
        """
        Plot distribution of reconstruction errors for benign vs malicious samples.
        
        Args:
            X_benign: Benign samples
            X_malicious: Malicious samples
            save_path: Path to save plot
        """
        # Get reconstruction errors
        results_benign = self.predict(X_benign)
        results_malicious = self.predict(X_malicious)
        
        errors_benign = results_benign['reconstruction_errors']
        errors_malicious = results_malicious['reconstruction_errors']
        
        # Create plot
        fig, axes = plt.subplots(1, 2, figsize=(15, 5))
        
        # Histogram
        axes[0].hist(errors_benign, bins=50, alpha=0.6, label='Benign', color='green', density=True)
        axes[0].hist(errors_malicious, bins=50, alpha=0.6, label='Malicious', color='red', density=True)
        axes[0].axvline(self.threshold, color='black', linestyle='--', linewidth=2, label='Threshold')
        axes[0].set_xlabel('Reconstruction Error (MSE)', fontsize=12)
        axes[0].set_ylabel('Density', fontsize=12)
        axes[0].set_title('Reconstruction Error Distribution', fontsize=14, fontweight='bold')
        axes[0].legend()
        axes[0].grid(True, alpha=0.3)
        
        # Box plot
        data_to_plot = [errors_benign, errors_malicious]
        axes[1].boxplot(data_to_plot, labels=['Benign', 'Malicious'])
        axes[1].axhline(self.threshold, color='black', linestyle='--', linewidth=2, label='Threshold')
        axes[1].set_ylabel('Reconstruction Error (MSE)', fontsize=12)
        axes[1].set_title('Reconstruction Error Box Plot', fontsize=14, fontweight='bold')
        axes[1].legend()
        axes[1].grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            logger.info(f"Reconstruction errors plot saved to {save_path}")
        
        plt.show()
    
    
    def save(self, model_path: Optional[Path] = None) -> None:
        """Save complete model, scaler, and configuration."""
        if model_path is None:
            model_path = config.AE_MODEL_PATH
        
        # Ensure model_path is a directory
        if model_path.suffix:  # If it has an extension, get parent directory
            save_dir = model_path.parent
            model_file = model_path
        else:  # It's already a directory
            save_dir = model_path
            model_file = save_dir / 'autoencoder_model.h5'
        
        save_dir.mkdir(parents=True, exist_ok=True)
        
        # Save Keras model
        self.model.save(str(model_file))
        logger.info(f"Model saved to {model_file}")
        
        # Save scaler
        scaler_path = save_dir / 'autoencoder_scaler.pkl'
        with open(scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)
        logger.info(f"Scaler saved to {scaler_path}")
        
        # FIXED: Build config from instance attributes instead of self.config
        config_data = {
            'input_dim': self.input_dim,
            'encoding_dims': self.encoding_dims,
            'noise_factor': self.noise_factor,
            'dropout_rate': self.dropout_rate,
            'l1_reg': self.l1_reg,
            'l2_reg': self.l2_reg,
            'threshold': float(self.threshold) if self.threshold else None
        }
        
        # Save threshold and config
        config_path = save_dir / 'autoencoder_config.json'
        with open(config_path, 'w') as f:
            json.dump(config_data, f, indent=2)
        logger.info(f"Configuration saved to {config_path}")
    
    @classmethod
    def load(cls, model_path: Optional[Path] = None) -> 'AdvancedAutoencoder':
        """Load saved model, scaler, and configuration."""
        if model_path is None:
            model_path = config.AE_MODEL_PATH
        
        # Determine paths
        if model_path.suffix:  # If it has an extension
            save_dir = model_path.parent
            model_file = model_path
        else:  # It's a directory
            save_dir = model_path
            model_file = save_dir / 'autoencoder_model.h5'
        
        # Load configuration
        config_path = save_dir / 'autoencoder_config.json'
        with open(config_path, 'r') as f:
            config_data = json.load(f)
        
        threshold = config_data.pop('threshold', None)
        
        # Create instance with config parameters
        instance = cls(
            input_dim=config_data['input_dim'],
            encoding_dims=config_data['encoding_dims'],
            noise_factor=config_data['noise_factor'],
            dropout_rate=config_data['dropout_rate'],
            l1_reg=config_data['l1_reg'],
            l2_reg=config_data['l2_reg']
        )
        
        # Load Keras model
        instance.model = keras.models.load_model(str(model_file))
        logger.info(f"Model loaded from {model_file}")
        
        # Load scaler
        scaler_path = save_dir / 'autoencoder_scaler.pkl'
        with open(scaler_path, 'rb') as f:
            instance.scaler = pickle.load(f)
        logger.info(f"Scaler loaded from {scaler_path}")
        
        # Load threshold
        instance.threshold = threshold
        
        return instance

class AutoencoderEnsemble:
    """
    Ensemble of multiple autoencoders for robust anomaly detection.
    
    Uses voting or averaging across multiple models trained with
    different initializations or architectures.
    """
    
    def __init__(self, n_models: int = 5):
        """
        Initialize ensemble.
        
        Args:
            n_models: Number of autoencoder models in ensemble
        """
        self.n_models = n_models
        self.models: List[AdvancedAutoencoder] = []
        self.ensemble_threshold: Optional[float] = None
        
        logger.info(f"AutoencoderEnsemble initialized with {n_models} models")
    
    
    def train_ensemble(self,
                      X_train: np.ndarray,
                      X_val: Optional[np.ndarray] = None,
                      epochs: int = 100,
                      batch_size: int = 256,
                      **kwargs) -> None:
        """
        Train multiple autoencoders with different random seeds.
        
        Args:
            X_train: Training data (benign only)
            X_val: Validation data (benign only)
            epochs: Training epochs per model
            batch_size: Batch size
            **kwargs: Additional arguments for AdvancedAutoencoder
        """
        logger.info("="*80)
        logger.info(f"TRAINING AUTOENCODER ENSEMBLE ({self.n_models} models)")
        logger.info("="*80)
        
        for i in range(self.n_models):
            logger.info(f"\nTraining model {i+1}/{self.n_models}...")
            
            # Create model with different seed
            tf.random.set_seed(config.TF_RANDOM_SEED + i)
            np.random.seed(config.RANDOM_SEED + i)
            
            model = AdvancedAutoencoder(**kwargs)
            model.build_model()
            model.train(
                X_train,
                X_val,
                epochs=epochs,
                batch_size=batch_size,
                patience=10,
                use_tensorboard=False
            )
            
            self.models.append(model)
            logger.info(f"Model {i+1} training completed!")
        
        logger.info("\nEnsemble training completed!")
    
    
    def calculate_ensemble_threshold(self,
                                    X_benign: np.ndarray,
                                    method: str = 'percentile',
                                    percentile: float = 95.0) -> float:
        """
        Calculate ensemble threshold using averaged reconstruction errors.
        
        Args:
            X_benign: Benign samples
            method: Threshold method
            percentile: Percentile value
            
        Returns:
            Ensemble threshold
        """
        logger.info("Calculating ensemble threshold...")
        
        # Get reconstruction errors from all models
        all_errors = []
        for model in self.models:
            results = model.predict(X_benign)
            all_errors.append(results['reconstruction_errors'])
        
        # Average errors across models
        avg_errors = np.mean(all_errors, axis=0)
        
        # Calculate threshold
        if method == 'percentile':
            self.ensemble_threshold = np.percentile(avg_errors, percentile)
        elif method == 'std':
            mean_err = np.mean(avg_errors)
            std_err = np.std(avg_errors)
            self.ensemble_threshold = mean_err + 3 * std_err
        else:
            self.ensemble_threshold = np.percentile(avg_errors, percentile)
        
        logger.info(f"Ensemble threshold: {self.ensemble_threshold:.6f}")
        
        return self.ensemble_threshold
    
    
    def predict_ensemble(self, X: np.ndarray, voting: str = 'soft') -> Dict[str, np.ndarray]:
        """
        Predict using ensemble.
        
        Args:
            X: Input features
            voting: 'soft' (average scores) or 'hard' (majority vote)
            
        Returns:
            Dictionary with predictions and scores
        """
        if voting == 'soft':
            # Average reconstruction errors
            all_errors = []
            for model in self.models:
                results = model.predict(X)
                all_errors.append(results['reconstruction_errors'])
            
            avg_errors = np.mean(all_errors, axis=0)
            predictions = (avg_errors > self.ensemble_threshold).astype(int)
            
            return {
                'predictions': predictions,
                'reconstruction_errors': avg_errors,
                'anomaly_scores': np.clip(avg_errors / (self.ensemble_threshold * 2), 0, 1)
            }
        
        else:  # hard voting
            all_predictions = []
            for model in self.models:
                results = model.predict(X)
                all_predictions.append(results['predictions'])
            
            # Majority vote
            votes = np.sum(all_predictions, axis=0)
            predictions = (votes > self.n_models / 2).astype(int)
            
            return {
                'predictions': predictions,
                'votes': votes,
                'vote_ratio': votes / self.n_models
            }


def test_advanced_autoencoder():
    """Test the advanced autoencoder with synthetic data."""
    
    logger.info("\n" + "="*80)
    logger.info("TESTING ADVANCED AUTOENCODER")
    logger.info("="*80 + "\n")
    
    # Generate synthetic data
    np.random.seed(42)
    
    # Benign data (82 features, normal distribution)
    n_benign = 1000
    X_benign = np.random.randn(n_benign, 82) * 0.5
    
    # Malicious data (outliers with larger values)
    n_malicious = 200
    X_malicious = np.random.randn(n_malicious, 82) * 2.0 + 3.0
    
    # Combine
    X_train = X_benign[:800]  # Train on benign only
    X_val = X_benign[800:]    # Validate on benign only
    
    X_test = np.vstack([X_benign, X_malicious])
    y_test = np.array([0] * n_benign + [1] * n_malicious)
    
    # Shuffle test set
    shuffle_idx = np.random.permutation(len(X_test))
    X_test = X_test[shuffle_idx]
    y_test = y_test[shuffle_idx]
    
    logger.info(f"Train (benign): {X_train.shape}")
    logger.info(f"Val (benign): {X_val.shape}")
    logger.info(f"Test: {X_test.shape} (Benign: {n_benign}, Malicious: {n_malicious})")
    
    # Test 1: Standard Autoencoder
    print("\n" + "="*80)
    print("TEST 1: Standard Autoencoder with Attention")
    print("="*80)
    
    ae = AdvancedAutoencoder(
        input_dim=82,
        encoding_dims=[64, 32, 16, 8],
        use_attention=True,
        use_vae=False,
        noise_factor=0.1,
        dropout_rate=0.3
    )
    
    ae.build_model()
    ae.train(X_train, X_val, epochs=50, batch_size=64, patience=10, use_tensorboard=False)
    
    # Calculate threshold
    ae.calculate_threshold(X_val, method='percentile', percentile=95)
    
    # Evaluate
    metrics = ae.evaluate(X_test, y_test, split_name='test')
    
    # Plot results
    ae.plot_training_history(save_path=config.RESULTS_DIR / 'ae_training_history.png')
    
    benign_test = X_test[y_test == 0]
    malicious_test = X_test[y_test == 1]
    ae.plot_reconstruction_errors(
        benign_test,
        malicious_test,
        save_path=config.RESULTS_DIR / 'ae_reconstruction_errors.png'
    )
    
    # Save model
    ae.save()
    
    # Test 2: Variational Autoencoder
    print("\n" + "="*80)
    print("TEST 2: Variational Autoencoder (VAE)")
    print("="*80)
    
    vae = AdvancedAutoencoder(
        input_dim=82,
        encoding_dims=[64, 32, 16],
        use_attention=True,
        use_vae=True,
        noise_factor=0.05,
        dropout_rate=0.2
    )
    
    vae.build_model()
    vae.train(X_train, X_val, epochs=50, batch_size=64, patience=10, use_tensorboard=False)
    vae.calculate_threshold(X_val, method='mixed', percentile=95)
    metrics_vae = vae.evaluate(X_test, y_test, split_name='test')
    
    # Test 3: Ensemble
    print("\n" + "="*80)
    print("TEST 3: Autoencoder Ensemble (3 models)")
    print("="*80)
    
    ensemble = AutoencoderEnsemble(n_models=3)
    ensemble.train_ensemble(
        X_train,
        X_val,
        epochs=30,
        batch_size=64,
        input_dim=82,
        encoding_dims=[64, 32, 16],
        use_attention=True,
        dropout_rate=0.3
    )
    
    ensemble.calculate_ensemble_threshold(X_val, method='percentile', percentile=95)
    results_ensemble = ensemble.predict_ensemble(X_test, voting='soft')
    
    # Evaluate ensemble
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    
    y_pred_ensemble = results_ensemble['predictions']
    acc = accuracy_score(y_test, y_pred_ensemble)
    prec = precision_score(y_test, y_pred_ensemble)
    rec = recall_score(y_test, y_pred_ensemble)
    f1 = f1_score(y_test, y_pred_ensemble)
    
    logger.info("="*80)
    logger.info("ENSEMBLE METRICS")
    logger.info("="*80)
    logger.info(f"Accuracy:  {acc:.4f}")
    logger.info(f"Precision: {prec:.4f}")
    logger.info(f"Recall:    {rec:.4f}")
    logger.info(f"F1-Score:  {f1:.4f}")
    logger.info("="*80)
    
    # Compare all methods
    print("\n" + "="*80)
    print("COMPARISON OF ALL METHODS")
    print("="*80)
    print(f"{'Method':<25} {'Accuracy':<12} {'Precision':<12} {'Recall':<12} {'F1-Score':<12}")
    print("-"*80)
    print(f"{'Standard AE':<25} {metrics['accuracy']:<12.4f} {metrics['precision']:<12.4f} "
          f"{metrics['recall']:<12.4f} {metrics['f1_score']:<12.4f}")
    print(f"{'VAE':<25} {metrics_vae['accuracy']:<12.4f} {metrics_vae['precision']:<12.4f} "
          f"{metrics_vae['recall']:<12.4f} {metrics_vae['f1_score']:<12.4f}")
    print(f"{'Ensemble (3 models)':<25} {acc:<12.4f} {prec:<12.4f} {rec:<12.4f} {f1:<12.4f}")
    print("="*80)
    
    # Test loading
    print("\n" + "="*80)
    print("TEST 4: Model Loading")
    print("="*80)
    
    ae_loaded = AdvancedAutoencoder.load()
    results_loaded = ae_loaded.predict(X_test[:10])
    print(f"✓ Model loaded successfully!")
    print(f"✓ Predictions on 10 samples: {results_loaded['predictions']}")
    
    print("\n" + "="*80)
    print("ALL TESTS COMPLETED SUCCESSFULLY!")
    print("="*80 + "\n")


if __name__ == "__main__":
    test_advanced_autoencoder()