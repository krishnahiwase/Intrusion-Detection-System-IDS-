"""
Machine Learning Anomaly Detection Module
Implements various ML algorithms for network intrusion detection
"""

import logging
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.cluster import DBSCAN
import joblib
import os

class AnomalyDetector:
    """Machine Learning Anomaly Detection for Network Traffic"""
    
    def __init__(self, model_type='isolation_forest'):
        """
        Initialize anomaly detector
        
        Args:
            model_type: Type of ML model ('isolation_forest', 'one_class_svm', 'random_forest', 'dbscan')
        """
        self.logger = logging.getLogger(__name__)
        self.model_type = model_type
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.is_trained = False
        self.feature_columns = None
        
        # Model parameters
        self.model_params = {
            'isolation_forest': {
                'contamination': 0.1,
                'n_estimators': 100,
                'max_samples': 'auto',
                'random_state': 42
            },
            'one_class_svm': {
                'nu': 0.1,
                'kernel': 'rbf',
                'gamma': 'scale'
            },
            'random_forest': {
                'n_estimators': 100,
                'max_depth': 10,
                'random_state': 42
            },
            'dbscan': {
                'eps': 0.5,
                'min_samples': 5
            }
        }
        
        self._initialize_model()
    
    def _initialize_model(self):
        """Initialize the ML model based on model_type"""
        try:
            if self.model_type == 'isolation_forest':
                self.model = IsolationForest(**self.model_params['isolation_forest'])
            elif self.model_type == 'one_class_svm':
                self.model = OneClassSVM(**self.model_params['one_class_svm'])
            elif self.model_type == 'random_forest':
                self.model = RandomForestClassifier(**self.model_params['random_forest'])
            elif self.model_type == 'dbscan':
                self.model = DBSCAN(**self.model_params['dbscan'])
            else:
                raise ValueError(f"Unknown model type: {self.model_type}")
            
            self.logger.info(f"Initialized {self.model_type} model")
            
        except Exception as e:
            self.logger.error(f"Error initializing model: {str(e)}")
            raise
    
    def preprocess_features(self, features_df, fit_scaler=False):
        """
        Preprocess features for ML model
        
        Args:
            features_df: DataFrame with features
            fit_scaler: Whether to fit the scaler (True for training)
            
        Returns:
            np.array: Preprocessed features
        """
        try:
            # Handle missing values
            features_df = features_df.fillna(0)
            
            # Select numeric columns
            numeric_features = features_df.select_dtypes(include=[np.number])
            
            # Remove any infinite or extremely large values
            numeric_features = numeric_features.replace([np.inf, -np.inf], 0)
            numeric_features = numeric_features.clip(-1e6, 1e6)
            
            # Scale features
            if fit_scaler:
                scaled_features = self.scaler.fit_transform(numeric_features)
            else:
                scaled_features = self.scaler.transform(numeric_features)
            
            self.feature_columns = numeric_features.columns.tolist()
            return scaled_features
            
        except Exception as e:
            self.logger.error(f"Error preprocessing features: {str(e)}")
            return np.array(features_df.select_dtypes(include=[np.number]))
    
    def train(self, features_df, labels=None):
        """
        Train the anomaly detection model
        
        Args:
            features_df: DataFrame with training features
            labels: Optional labels for supervised learning
        """
        try:
            self.logger.info(f"Training {self.model_type} model with {len(features_df)} samples")
            
            # Preprocess features
            X_train = self.preprocess_features(features_df, fit_scaler=True)
            
            # Train model based on type
            if self.model_type in ['isolation_forest', 'one_class_svm']:
                # Unsupervised learning
                self.model.fit(X_train)
                
            elif self.model_type == 'random_forest':
                # Supervised learning
                if labels is None:
                    # Create synthetic labels (assume normal traffic)
                    labels = np.zeros(len(X_train))
                self.model.fit(X_train, labels)
                
            elif self.model_type == 'dbscan':
                # Clustering-based
                self.model.fit(X_train)
            
            self.is_trained = True
            self.logger.info("Model training completed")
            
            # Log model performance if validation data available
            if labels is not None and self.model_type != 'dbscan':
                self._log_training_performance(X_train, labels)
            
        except Exception as e:
            self.logger.error(f"Error training model: {str(e)}")
            raise
    
    def predict(self, features_df):
        """
        Predict anomalies on new data
        
        Args:
            features_df: DataFrame with features to predict
            
        Returns:
            dict: Prediction results with scores and classifications
        """
        try:
            if not self.is_trained:
                raise ValueError("Model must be trained before making predictions")
            
            # Preprocess features
            X_test = self.preprocess_features(features_df, fit_scaler=False)
            
            # Make predictions based on model type
            if self.model_type == 'isolation_forest':
                predictions = self.model.predict(X_test)
                scores = self.model.decision_function(X_test)
                # Convert from {-1, 1} to {0, 1} where -1 is anomaly
                anomaly_predictions = (predictions == -1).astype(int)
                
            elif self.model_type == 'one_class_svm':
                predictions = self.model.predict(X_test)
                scores = self.model.decision_function(X_test)
                anomaly_predictions = (predictions == -1).astype(int)
                
            elif self.model_type == 'random_forest':
                predictions = self.model.predict(X_test)
                scores = self.model.predict_proba(X_test)[:, 1] if hasattr(self.model, 'predict_proba') else predictions
                anomaly_predictions = predictions.astype(int)
                
            elif self.model_type == 'dbscan':
                cluster_labels = self.model.fit_predict(X_test)
                # Anomalies are points labeled as -1 (noise)
                anomaly_predictions = (cluster_labels == -1).astype(int)
                scores = np.ones(len(X_test))  # Placeholder scores
            
            return {
                'predictions': anomaly_predictions,
                'scores': scores,
                'anomaly_count': np.sum(anomaly_predictions),
                'anomaly_rate': np.mean(anomaly_predictions),
                'confidence': self._calculate_confidence(scores, anomaly_predictions)
            }
            
        except Exception as e:
            self.logger.error(f"Error making predictions: {str(e)}")
            return {
                'predictions': np.zeros(len(features_df)),
                'scores': np.zeros(len(features_df)),
                'anomaly_count': 0,
                'anomaly_rate': 0.0,
                'confidence': 0.0
            }
    
    def _calculate_confidence(self, scores, predictions):
        """Calculate prediction confidence"""
        try:
            if self.model_type == 'isolation_forest':
                # Normalize scores to [0, 1]
                normalized_scores = (scores - scores.min()) / (scores.max() - scores.min() + 1e-10)
                return np.mean(1 - normalized_scores)
            elif self.model_type == 'one_class_svm':
                return np.mean(np.abs(scores))
            elif self.model_type == 'random_forest':
                return np.mean(scores)
            else:
                return 0.5
        except:
            return 0.5
    
    def _log_training_performance(self, X_train, y_train):
        """Log model performance metrics"""
        try:
            if self.model_type == 'random_forest':
                train_score = self.model.score(X_train, y_train)
                self.logger.info(f"Training accuracy: {train_score:.3f}")
                
                # Cross-validation
                cv_scores = cross_val_score(self.model, X_train, y_train, cv=3)
                self.logger.info(f"Cross-validation scores: {cv_scores}")
                self.logger.info(f"Mean CV score: {np.mean(cv_scores):.3f}")
            
        except Exception as e:
            self.logger.warning(f"Could not log training performance: {str(e)}")
    
    def evaluate_model(self, X_test, y_test):
        """
        Evaluate model performance
        
        Args:
            X_test: Test features
            y_test: Test labels
            
        Returns:
            dict: Evaluation metrics
        """
        try:
            if not self.is_trained:
                raise ValueError("Model must be trained before evaluation")
            
            # Preprocess test data
            X_test_processed = self.preprocess_features(X_test, fit_scaler=False)
            
            # Make predictions
            results = self.predict(X_test)
            predictions = results['predictions']
            
            # Calculate metrics
            accuracy = np.mean(predictions == y_test)
            
            # Classification report
            report = classification_report(y_test, predictions, output_dict=True)
            
            # Confusion matrix
            cm = confusion_matrix(y_test, predictions)
            
            # ROC AUC (if binary classification)
            try:
                auc = roc_auc_score(y_test, results['scores'])
            except:
                auc = None
            
            evaluation_results = {
                'accuracy': accuracy,
                'precision': report.get('weighted avg', {}).get('precision', 0),
                'recall': report.get('weighted avg', {}).get('recall', 0),
                'f1_score': report.get('weighted avg', {}).get('f1-score', 0),
                'confusion_matrix': cm,
                'roc_auc': auc,
                'classification_report': report
            }
            
            self.logger.info(f"Model evaluation - Accuracy: {accuracy:.3f}, F1: {evaluation_results['f1_score']:.3f}")
            return evaluation_results
            
        except Exception as e:
            self.logger.error(f"Error evaluating model: {str(e)}")
            return {'accuracy': 0, 'precision': 0, 'recall': 0, 'f1_score': 0}
    
    def save_model(self, filepath):
        """Save trained model to file"""
        try:
            if not self.is_trained:
                raise ValueError("Model must be trained before saving")
            
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'model_type': self.model_type,
                'feature_columns': self.feature_columns,
                'is_trained': self.is_trained,
                'model_params': self.model_params[self.model_type]
            }
            
            joblib.dump(model_data, filepath)
            self.logger.info(f"Model saved to {filepath}")
            
        except Exception as e:
            self.logger.error(f"Error saving model: {str(e)}")
            raise
    
    def load_model(self, filepath):
        """Load trained model from file"""
        try:
            if not os.path.exists(filepath):
                raise FileNotFoundError(f"Model file not found: {filepath}")
            
            model_data = joblib.load(filepath)
            
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.model_type = model_data['model_type']
            self.feature_columns = model_data['feature_columns']
            self.is_trained = model_data['is_trained']
            
            self.logger.info(f"Model loaded from {filepath}")
            
        except Exception as e:
            self.logger.error(f"Error loading model: {str(e)}")
            raise
    
    def get_feature_importance(self):
        """Get feature importance from the model"""
        try:
            if not self.is_trained:
                return {}
            
            importance_dict = {}
            
            if self.model_type == 'random_forest':
                if hasattr(self.model, 'feature_importances_'):
                    for i, importance in enumerate(self.model.feature_importances_):
                        if self.feature_columns and i < len(self.feature_columns):
                            importance_dict[self.feature_columns[i]] = importance
                        else:
                            importance_dict[f'feature_{i}'] = importance
            
            elif self.model_type == 'isolation_forest':
                # Isolation Forest doesn't provide direct feature importance
                # Return a placeholder
                if self.feature_columns:
                    for col in self.feature_columns:
                        importance_dict[col] = 1.0 / len(self.feature_columns)
            
            return importance_dict
            
        except Exception as e:
            self.logger.error(f"Error getting feature importance: {str(e)}")
            return {}
    
    def detect_anomalies_realtime(self, features_df, threshold=0.5):
        """
        Real-time anomaly detection with threshold
        
        Args:
            features_df: DataFrame with features
            threshold: Anomaly threshold (0-1)
            
        Returns:
            list: Indices of anomalous packets
        """
        try:
            results = self.predict(features_df)
            
            # Apply threshold to scores
            if self.model_type in ['isolation_forest', 'one_class_svm']:
                anomaly_indices = np.where(results['scores'] < threshold)[0]
            else:
                anomaly_indices = np.where(results['predictions'] == 1)[0]
            
            return anomaly_indices.tolist()
            
        except Exception as e:
            self.logger.error(f"Error in real-time detection: {str(e)}")
            return []