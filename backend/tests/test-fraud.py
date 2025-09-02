"""
Fraud Detection Tests for Fraud Detection System

This module contains comprehensive tests for fraud detection algorithms, machine learning models,
risk scoring, pattern recognition, and fraud prevention features.
"""

import pytest
import asyncio
import json
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from fastapi.testclient import TestClient
from fastapi import status
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score

# Local imports
from app.services.fraud_detection_service import FraudDetectionService
from app.core.ml_models import (
    FraudDetectionModel,
    RiskScoringModel,
    AnomalyDetectionModel,
    ModelTrainer,
    ModelEvaluator
)
from app.core.fraud_rules import (
    RuleEngine,
    VelocityRule,
    LocationRule,
    AmountRule,
    PatternRule
)
from app.services.risk_assessment_service import RiskAssessmentService
from app.services.transaction_analyzer import TransactionAnalyzer
from app.models.transaction import Transaction
from app.models.fraud_alert import FraudAlert
from tests import TestDataFactory, PerformanceTimer, MLTestHelper


class TestFraudDetectionService:
    """Test fraud detection service functionality"""
    
    @pytest.fixture
    def fraud_service(self, test_db, test_redis):
        """Create fraud detection service instance"""
        return FraudDetectionService(db_session=test_db, redis_client=test_redis)
    
    @pytest.fixture
    def sample_transaction(self):
        """Create sample transaction for testing"""
        return TestDataFactory.create_transaction(
            id="txn_test_001",
            user_id=1,
            amount=150.00,
            merchant_id="merchant_001",
            location="New York, NY",
            timestamp=datetime.utcnow(),
            card_number="****1234",
            transaction_type="purchase"
        )
    
    @pytest.fixture
    def high_risk_transaction(self):
        """Create high-risk transaction for testing"""
        return TestDataFactory.create_transaction(
            id="txn_risk_001",
            user_id=1,
            amount=5000.00,  # High amount
            merchant_id="merchant_unknown",
            location="Unknown Location",
            timestamp=datetime.utcnow(),
            card_number="****5678",
            transaction_type="cash_advance"
        )
    
    def test_analyze_transaction_low_risk(self, fraud_service, sample_transaction):
        """Test analysis of low-risk transaction"""
        result = fraud_service.analyze_transaction(sample_transaction)
        
        assert result is not None
        assert "fraud_score" in result
        assert "risk_level" in result
        assert "indicators" in result
        assert "model_version" in result
        
        # Low-risk transaction should have low fraud score
        assert 0 <= result["fraud_score"] <= 1
        assert result["risk_level"] in ["low", "medium", "high"]
        assert isinstance(result["indicators"], list)
    
    def test_analyze_transaction_high_risk(self, fraud_service, high_risk_transaction):
        """Test analysis of high-risk transaction"""
        result = fraud_service.analyze_transaction(high_risk_transaction)
        
        assert result is not None
        assert result["fraud_score"] > 0.5  # Should be higher risk
        assert result["risk_level"] in ["medium", "high"]
        assert len(result["indicators"]) > 0  # Should have risk indicators
    
    def test_batch_transaction_analysis(self, fraud_service):
        """Test batch analysis of multiple transactions"""
        transactions = [
            TestDataFactory.create_transaction(id=f"txn_{i}", amount=100 + i*10)
            for i in range(10)
        ]
        
        results = fraud_service.analyze_transactions_batch(transactions)
        
        assert len(results) == 10
        for result in results:
            assert "fraud_score" in result
            assert "transaction_id" in result
    
    def test_real_time_fraud_detection(self, fraud_service, sample_transaction):
        """Test real-time fraud detection"""
        with PerformanceTimer() as timer:
            result = fraud_service.detect_fraud_realtime(sample_transaction)
        
        # Should complete quickly for real-time processing
        assert timer.elapsed_ms < 500  # Under 500ms
        assert result["processing_time"] < 0.5
        assert "decision" in result  # approve/decline/review
    
    def test_fraud_pattern_detection(self, fraud_service):
        """Test fraud pattern detection"""
        # Create transactions with suspicious patterns
        suspicious_transactions = []
        
        # Pattern 1: Multiple transactions in short time
        base_time = datetime.utcnow()
        for i in range(5):
            txn = TestDataFactory.create_transaction(
                id=f"velocity_{i}",
                user_id=1,
                amount=200.00,
                timestamp=base_time + timedelta(minutes=i)
            )
            suspicious_transactions.append(txn)
        
        # Analyze pattern
        pattern_result = fraud_service.detect_patterns(suspicious_transactions)
        
        assert "velocity_pattern" in pattern_result
        assert pattern_result["velocity_pattern"]["detected"] is True
        assert pattern_result["velocity_pattern"]["risk_score"] > 0.7
    
    def test_user_behavior_analysis(self, fraud_service):
        """Test user behavior analysis"""
        user_id = 1
        
        # Create historical transactions for user
        historical_transactions = [
            TestDataFactory.create_transaction(
                user_id=user_id,
                amount=50 + i*10,
                location="New York, NY",
                timestamp=datetime.utcnow() - timedelta(days=i)
            )
            for i in range(30)  # 30 days of history
        ]
        
        # Analyze new transaction against user behavior
        new_transaction = TestDataFactory.create_transaction(
            user_id=user_id,
            amount=1000.00,  # Much higher than usual
            location="Las Vegas, NV"  # Different location
        )
        
        behavior_analysis = fraud_service.analyze_user_behavior(
            new_transaction, 
            historical_transactions
        )
        
        assert "behavior_score" in behavior_analysis
        assert "anomalies" in behavior_analysis
        assert "typical_patterns" in behavior_analysis
        
        # Should detect amount and location anomalies
        anomalies = behavior_analysis["anomalies"]
        assert any("amount" in anomaly for anomaly in anomalies)
        assert any("location" in anomaly for anomaly in anomalies)
    
    def test_merchant_risk_assessment(self, fraud_service):
        """Test merchant risk assessment"""
        merchant_id = "merchant_suspicious"
        
        # Create transactions for merchant analysis
        merchant_transactions = [
            TestDataFactory.create_transaction(
                merchant_id=merchant_id,
                amount=100 + i*50,
                user_id=i % 10  # Different users
            )
            for i in range(20)
        ]
        
        risk_assessment = fraud_service.assess_merchant_risk(
            merchant_id, 
            merchant_transactions
        )
        
        assert "risk_score" in risk_assessment
        assert "risk_factors" in risk_assessment
        assert "transaction_patterns" in risk_assessment
        assert 0 <= risk_assessment["risk_score"] <= 1
    
    def test_fraud_alert_generation(self, fraud_service, high_risk_transaction):
        """Test fraud alert generation"""
        # Analyze high-risk transaction
        analysis_result = fraud_service.analyze_transaction(high_risk_transaction)
        
        # Generate alert if fraud score is high
        if analysis_result["fraud_score"] > 0.8:
            alert = fraud_service.generate_fraud_alert(
                high_risk_transaction,
                analysis_result
            )
            
            assert alert is not None
            assert alert["transaction_id"] == high_risk_transaction["id"]
            assert alert["alert_type"] == "high_fraud_score"
            assert alert["severity"] in ["medium", "high", "critical"]
    
    def test_false_positive_handling(self, fraud_service):
        """Test false positive handling and learning"""
        transaction = TestDataFactory.create_transaction(
            id="txn_fp_001",
            amount=500.00
        )
        
        # Initial analysis flags as fraud
        initial_result = fraud_service.analyze_transaction(transaction)
        
        # User confirms it's legitimate (false positive)
        fraud_service.mark_false_positive(
            transaction["id"],
            user_feedback="legitimate_purchase",
            reason="user_confirmed"
        )
        
        # System should learn from this feedback
        updated_result = fraud_service.analyze_transaction(transaction)
        
        # Fraud score should be adjusted based on feedback
        assert updated_result["fraud_score"] <= initial_result["fraud_score"]
    
    @patch('app.services.external_fraud_api.check_blacklist')
    def test_external_fraud_data_integration(self, mock_blacklist, fraud_service):
        """Test integration with external fraud data sources"""
        mock_blacklist.return_value = {
            "is_blacklisted": True,
            "reason": "stolen_card",
            "confidence": 0.95
        }
        
        transaction = TestDataFactory.create_transaction(
            card_number="****9999"  # Blacklisted card
        )
        
        result = fraud_service.analyze_transaction(transaction)
        
        # Should incorporate external fraud data
        assert result["fraud_score"] > 0.9  # High score due to blacklist
        assert "external_fraud_data" in result
        assert result["external_fraud_data"]["is_blacklisted"] is True


class TestFraudDetectionModels:
    """Test machine learning fraud detection models"""
    
    @pytest.fixture
    def model_trainer(self):
        """Create model trainer instance"""
        return ModelTrainer()
    
    @pytest.fixture
    def training_data(self):
        """Create training data for ML models"""
        return MLTestHelper.generate_fraud_training_data(
            num_samples=1000,
            fraud_ratio=0.1  # 10% fraud cases
        )
    
    @pytest.fixture
    def test_data(self):
        """Create test data for model evaluation"""
        return MLTestHelper.generate_fraud_test_data(
            num_samples=200,
            fraud_ratio=0.1
        )
    
    def test_fraud_detection_model_training(self, model_trainer, training_data):
        """Test fraud detection model training"""
        X_train, y_train = training_data
        
        # Train model
        model = model_trainer.train_fraud_detection_model(X_train, y_train)
        
        assert model is not None
        assert hasattr(model, 'predict')
        assert hasattr(model, 'predict_proba')
        
        # Test model can make predictions
        sample_features = X_train[:5]
        predictions = model.predict(sample_features)
        probabilities = model.predict_proba(sample_features)
        
        assert len(predictions) == 5
        assert len(probabilities) == 5
        assert all(pred in [0, 1] for pred in predictions)
    
    def test_model_performance_evaluation(self, model_trainer, training_data, test_data):
        """Test model performance evaluation"""
        X_train, y_train = training_data
        X_test, y_test = test_data
        
        # Train model
        model = model_trainer.train_fraud_detection_model(X_train, y_train)
        
        # Evaluate model
        evaluator = ModelEvaluator()
        metrics = evaluator.evaluate_model(model, X_test, y_test)
        
        assert "accuracy" in metrics
        assert "precision" in metrics
        assert "recall" in metrics
        assert "f1_score" in metrics
        assert "auc_roc" in metrics
        
        # Model should perform reasonably well
        assert metrics["accuracy"] > 0.8
        assert metrics["precision"] > 0.7
        assert metrics["recall"] > 0.6
    
    def test_feature_importance_analysis(self, model_trainer, training_data):
        """Test feature importance analysis"""
        X_train, y_train = training_data
        
        # Train model with feature names
        feature_names = [
            "amount", "hour_of_day", "day_of_week", "merchant_risk_score",
            "user_velocity", "location_risk", "card_age", "transaction_frequency"
        ]
        
        model = model_trainer.train_fraud_detection_model(
            X_train, y_train, feature_names=feature_names
        )
        
        # Get feature importance
        importance = model_trainer.get_feature_importance(model, feature_names)
        
        assert len(importance) == len(feature_names)
        assert all(score >= 0 for score in importance.values())
        
        # Sum of importance scores should be reasonable
        total_importance = sum(importance.values())
        assert 0.8 <= total_importance <= 1.2
    
    def test_model_cross_validation(self, model_trainer, training_data):
        """Test model cross-validation"""
        X_train, y_train = training_data
        
        # Perform cross-validation
        cv_scores = model_trainer.cross_validate_model(
            X_train, y_train, cv_folds=5
        )
        
        assert len(cv_scores) == 5
        assert all(0 <= score <= 1 for score in cv_scores)
        
        # Calculate mean and std of CV scores
        mean_score = np.mean(cv_scores)
        std_score = np.std(cv_scores)
        
        assert mean_score > 0.7  # Reasonable performance
        assert std_score < 0.1   # Consistent performance
    
    def test_model_hyperparameter_tuning(self, model_trainer, training_data):
        """Test hyperparameter tuning"""
        X_train, y_train = training_data
        
        # Define hyperparameter grid
        param_grid = {
            'n_estimators': [50, 100],
            'max_depth': [5, 10],
            'min_samples_split': [2, 5]
        }
        
        # Tune hyperparameters
        best_model, best_params = model_trainer.tune_hyperparameters(
            X_train, y_train, param_grid
        )
        
        assert best_model is not None
        assert best_params is not None
        assert "n_estimators" in best_params
        assert "max_depth" in best_params
    
    def test_ensemble_model_training(self, model_trainer, training_data):
        """Test ensemble model training"""
        X_train, y_train = training_data
        
        # Train ensemble model
        ensemble_model = model_trainer.train_ensemble_model(X_train, y_train)
        
        assert ensemble_model is not None
        
        # Test ensemble predictions
        sample_features = X_train[:10]
        predictions = ensemble_model.predict(sample_features)
        probabilities = ensemble_model.predict_proba(sample_features)
        
        assert len(predictions) == 10
        assert len(probabilities) == 10
    
    def test_model_versioning_and_deployment(self, model_trainer, training_data):
        """Test model versioning and deployment"""
        X_train, y_train = training_data
        
        # Train model
        model = model_trainer.train_fraud_detection_model(X_train, y_train)
        
        # Save model with version
        model_version = "v1.0.0"
        model_path = model_trainer.save_model(model, model_version)
        
        assert model_path is not None
        
        # Load model
        loaded_model = model_trainer.load_model(model_version)
        
        assert loaded_model is not None
        
        # Test loaded model works
        sample_features = X_train[:5]
        original_predictions = model.predict(sample_features)
        loaded_predictions = loaded_model.predict(sample_features)
        
        np.testing.assert_array_equal(original_predictions, loaded_predictions)
    
    def test_online_learning_capability(self, model_trainer, training_data):
        """Test online learning and model updates"""
        X_train, y_train = training_data
        
        # Train initial model
        model = model_trainer.train_fraud_detection_model(X_train, y_train)
        
        # Generate new training data (simulating new fraud patterns)
        X_new, y_new = MLTestHelper.generate_fraud_training_data(
            num_samples=100,
            fraud_ratio=0.2  # Higher fraud ratio
        )
        
        # Update model with new data
        updated_model = model_trainer.update_model_online(model, X_new, y_new)
        
        assert updated_model is not None
        
        # Model should adapt to new patterns
        # This would require more sophisticated testing in practice


class TestRuleEngine:
    """Test rule-based fraud detection"""
    
    @pytest.fixture
    def rule_engine(self):
        """Create rule engine instance"""
        return RuleEngine()
    
    def test_velocity_rule(self, rule_engine):
        """Test velocity-based fraud rule"""
        velocity_rule = VelocityRule(
            max_transactions=3,
            time_window_minutes=5,
            threshold_amount=1000.00
        )
        
        rule_engine.add_rule(velocity_rule)
        
        # Create transactions that violate velocity rule
        base_time = datetime.utcnow()
        transactions = [
            TestDataFactory.create_transaction(
                user_id=1,
                amount=400.00,
                timestamp=base_time + timedelta(minutes=i)
            )
            for i in range(4)  # 4 transactions in 4 minutes
        ]
        
        # Test rule evaluation
        for i, txn in enumerate(transactions):
            result = rule_engine.evaluate_transaction(txn, transactions[:i])
            
            if i >= 3:  # 4th transaction should trigger rule
                assert result["velocity_rule"]["triggered"] is True
                assert result["velocity_rule"]["risk_score"] > 0.7
    
    def test_location_rule(self, rule_engine):
        """Test location-based fraud rule"""
        location_rule = LocationRule(
            max_distance_km=100,
            time_window_hours=1
        )
        
        rule_engine.add_rule(location_rule)
        
        # Create transactions in different locations
        txn1 = TestDataFactory.create_transaction(
            user_id=1,
            location="New York, NY",
            timestamp=datetime.utcnow()
        )
        
        txn2 = TestDataFactory.create_transaction(
            user_id=1,
            location="Los Angeles, CA",  # ~2500 miles away
            timestamp=datetime.utcnow() + timedelta(minutes=30)
        )
        
        # Evaluate location rule
        result = rule_engine.evaluate_transaction(txn2, [txn1])
        
        assert result["location_rule"]["triggered"] is True
        assert result["location_rule"]["risk_score"] > 0.8
    
    def test_amount_rule(self, rule_engine):
        """Test amount-based fraud rule"""
        amount_rule = AmountRule(
            max_amount=1000.00,
            user_average_multiplier=5.0
        )
        
        rule_engine.add_rule(amount_rule)
        
        # Create transaction with high amount
        high_amount_txn = TestDataFactory.create_transaction(
            user_id=1,
            amount=5000.00  # High amount
        )
        
        # Create user's historical transactions (low amounts)
        historical_txns = [
            TestDataFactory.create_transaction(
                user_id=1,
                amount=50.00 + i*10
            )
            for i in range(10)
        ]
        
        # Evaluate amount rule
        result = rule_engine.evaluate_transaction(high_amount_txn, historical_txns)
        
        assert result["amount_rule"]["triggered"] is True
        assert result["amount_rule"]["risk_score"] > 0.6
    
    def test_pattern_rule(self, rule_engine):
        """Test pattern-based fraud rule"""
        pattern_rule = PatternRule(
            suspicious_patterns=[
            "round_amounts",  # $100, $200, $500, etc.
            "sequential_merchants",  # Same merchant multiple times
            "unusual_hours"  # Transactions at 3 AM
            ]
        )
        
        rule_engine.add_rule(pattern_rule)
        
        # Create transaction with suspicious pattern (round amount at unusual hour)
        suspicious_txn = TestDataFactory.create_transaction(
            user_id=1,
            amount=500.00,  # Round amount
            timestamp=datetime.utcnow().replace(hour=3, minute=0)  # 3 AM
        )
        
        result = rule_engine.evaluate_transaction(suspicious_txn, [])
        
        assert result["pattern_rule"]["triggered"] is True
        assert "round_amounts" in result["pattern_rule"]["matched_patterns"]
        assert "unusual_hours" in result["pattern_rule"]["matched_patterns"]
    
    def test_rule_combination_logic(self, rule_engine):
        """Test combination of multiple rules"""
        # Add multiple rules
        rule_engine.add_rule(VelocityRule(max_transactions=2, time_window_minutes=5))
        rule_engine.add_rule(AmountRule(max_amount=1000.00))
        
        # Create transaction that triggers multiple rules
        base_time = datetime.utcnow()
        transactions = [
            TestDataFactory.create_transaction(
                user_id=1,
                amount=800.00,
                timestamp=base_time
            ),
            TestDataFactory.create_transaction(
                user_id=1,
                amount=900.00,
                timestamp=base_time + timedelta(minutes=2)
            ),
            TestDataFactory.create_transaction(
                user_id=1,
                amount=1200.00,  # High amount + 3rd transaction in 5 min
                timestamp=base_time + timedelta(minutes=4)
            )
        ]
        
        # Evaluate final transaction
        result = rule_engine.evaluate_transaction(transactions[2], transactions[:2])
        
        # Should trigger both velocity and amount rules
        assert result["velocity_rule"]["triggered"] is True
        assert result["amount_rule"]["triggered"] is True
        
        # Combined risk score should be higher
        combined_score = rule_engine.calculate_combined_risk_score(result)
        assert combined_score > 0.8
    
    def test_rule_configuration_and_updates(self, rule_engine):
        """Test rule configuration and dynamic updates"""
        # Configure rule with specific parameters
        velocity_rule = VelocityRule(
            max_transactions=5,
            time_window_minutes=10
        )
        
        rule_engine.add_rule(velocity_rule)
        
        # Update rule configuration
        rule_engine.update_rule_config("velocity_rule", {
            "max_transactions": 3,
            "time_window_minutes": 5
        })
        
        # Test updated rule behavior
        transactions = [
            TestDataFactory.create_transaction(user_id=1)
            for _ in range(4)
        ]
        
        result = rule_engine.evaluate_transaction(transactions[3], transactions[:3])
        
        # Should trigger with updated (stricter) configuration
        assert result["velocity_rule"]["triggered"] is True


class TestRiskAssessmentService:
    """Test risk assessment service"""
    
    @pytest.fixture
    def risk_service(self, test_db, test_redis):
        """Create risk assessment service"""
        return RiskAssessmentService(db_session=test_db, redis_client=test_redis)
    
    def test_transaction_risk_scoring(self, risk_service):
        """Test transaction risk scoring"""
        transaction = TestDataFactory.create_transaction(
            amount=750.00,
            merchant_id="merchant_medium_risk",
            location="Chicago, IL"
        )
        
        risk_score = risk_service.calculate_transaction_risk_score(transaction)
        
        assert 0 <= risk_score <= 1
        assert isinstance(risk_score, float)
    
    def test_user_risk_profiling(self, risk_service):
        """Test user risk profiling"""
        user_id = 1
        
        # Create user transaction history
        historical_transactions = [
            TestDataFactory.create_transaction(
                user_id=user_id,
                amount=100 + i*20,
                timestamp=datetime.utcnow() - timedelta(days=i)
            )
            for i in range(30)
        ]
        
        risk_profile = risk_service.create_user_risk_profile(
            user_id, 
            historical_transactions
        )
        
        assert "risk_score" in risk_profile
        assert "spending_patterns" in risk_profile
        assert "behavioral_indicators" in risk_profile
        assert "risk_factors" in risk_profile
    
    def test_merchant_risk_evaluation(self, risk_service):
        """Test merchant risk evaluation"""
        merchant_id = "merchant_test_001"
        
        # Create merchant transaction data
        merchant_transactions = [
            TestDataFactory.create_transaction(
                merchant_id=merchant_id,
                user_id=i % 20,  # Different users
                amount=50 + i*25
            )
            for i in range(100)
        ]
        
        risk_evaluation = risk_service.evaluate_merchant_risk(
            merchant_id,
            merchant_transactions
        )
        
        assert "risk_score" in risk_evaluation
        assert "transaction_volume" in risk_evaluation
        assert "chargeback_rate" in risk_evaluation
        assert "user_diversity" in risk_evaluation
    
    def test_geographic_risk_assessment(self, risk_service):
        """Test geographic risk assessment"""
        locations = [
            "New York, NY",
            "Los Angeles, CA", 
            "Chicago, IL",
            "Unknown Location",
            "High Risk Country"
        ]
        
        for location in locations:
            risk_score = risk_service.assess_geographic_risk(location)
            
            assert 0 <= risk_score <= 1
            
            # Unknown locations should have higher risk
            if "Unknown" in location or "High Risk" in location:
                assert risk_score > 0.6
    
    def test_device_risk_assessment(self, risk_service):
        """Test device and IP risk assessment"""
        device_info = {
            "ip_address": "192.168.1.100",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "device_fingerprint": "fp_12345",
            "is_mobile": False,
            "is_tor": False
        }
        
        risk_assessment = risk_service.assess_device_risk(device_info)
        
        assert "risk_score" in risk_assessment
        assert "risk_factors" in risk_assessment
        
        # Test high-risk device
        high_risk_device = {
            "ip_address": "10.0.0.1",  # Private IP (suspicious)
            "user_agent": "Unknown",
            "is_tor": True,  # Tor usage
            "device_fingerprint": None
        }
        
        high_risk_assessment = risk_service.assess_device_risk(high_risk_device)
        assert high_risk_assessment["risk_score"] > 0.7
    
    def test_temporal_risk_analysis(self, risk_service):
        """Test temporal risk analysis"""
        # Test different times of day
        timestamps = [
            datetime.utcnow().replace(hour=2, minute=30),   # 2:30 AM (high risk)
            datetime.utcnow().replace(hour=14, minute=0),   # 2:00 PM (normal)
            datetime.utcnow().replace(hour=23, minute=45)   # 11:45 PM (medium risk)
        ]
        
        for timestamp in timestamps:
            risk_score = risk_service.assess_temporal_risk(timestamp)
            assert 0 <= risk_score <= 1
            
            # Early morning hours should have higher risk
            if timestamp.hour < 6:
                assert risk_score > 0.5


class TestTransactionAnalyzer:
    """Test transaction analysis functionality"""
    
    @pytest.fixture
    def analyzer(self, test_db, test_redis):
        """Create transaction analyzer"""
        return TransactionAnalyzer(db_session=test_db, redis_client=test_redis)
    
    def test_transaction_feature_extraction(self, analyzer):
        """Test feature extraction from transactions"""
        transaction = TestDataFactory.create_transaction(
            amount=250.00,
            timestamp=datetime.utcnow(),
            merchant_id="merchant_001",
            location="New York, NY"
        )
        
        features = analyzer.extract_features(transaction)
        
        expected_features = [
            "amount", "hour_of_day", "day_of_week", "merchant_category",
            "location_risk", "amount_zscore", "transaction_frequency"
        ]
        
        for feature in expected_features:
            assert feature in features
        
        assert isinstance(features["amount"], (int, float))
        assert 0 <= features["hour_of_day"] <= 23
        assert 0 <= features["day_of_week"] <= 6
    
    def test_anomaly_detection(self, analyzer):
        """Test anomaly detection in transactions"""
        # Create normal transactions
        normal_transactions = [
            TestDataFactory.create_transaction(
                user_id=1,
                amount=50 + i*10,
                location="New York, NY"
            )
            for i in range(20)
        ]
        
        # Create anomalous transaction
        anomalous_transaction = TestDataFactory.create_transaction(
            user_id=1,
            amount=5000.00,  # Much higher than normal
            location="Unknown Location"
        )
        
        # Detect anomaly
        is_anomaly, anomaly_score = analyzer.detect_anomaly(
            anomalous_transaction,
            normal_transactions
        )
        
        assert is_anomaly is True
        assert anomaly_score > 0.7
    
    def test_spending_pattern_analysis(self, analyzer):
        """Test spending pattern analysis"""
        user_id = 1
        
        # Create transactions with patterns
        transactions = []
        
        # Weekly grocery shopping pattern
        for week in range(4):
            grocery_txn = TestDataFactory.create_transaction(
                user_id=user_id,
                amount=150.00,
                merchant_id="grocery_store",
                timestamp=datetime.utcnow() - timedelta(days=week*7)
            )
            transactions.append(grocery_txn)
        
        # Daily coffee purchases
        for day in range(20):
            coffee_txn = TestDataFactory.create_transaction(
                user_id=user_id,
                amount=5.50,
                merchant_id="coffee_shop",
                timestamp=datetime.utcnow() - timedelta(days=day)
            )
            transactions.append(coffee_txn)
        
        patterns = analyzer.analyze_spending_patterns(user_id, transactions)
        
        assert "recurring_merchants" in patterns
        assert "spending_frequency" in patterns
        assert "amount_patterns" in patterns
        
        # Should detect grocery and coffee patterns
        recurring = patterns["recurring_merchants"]
        assert any("grocery" in merchant.lower() for merchant in recurring)
        assert any("coffee" in merchant.lower() for merchant in recurring)
    
    def test_velocity_analysis(self, analyzer):
        """Test transaction velocity analysis"""
        user_id = 1
        base_time = datetime.utcnow()
        
        # Create high-velocity transactions
        velocity_transactions = [
            TestDataFactory.create_transaction(
                user_id=user_id,
                amount=200.00,
                timestamp=base_time + timedelta(minutes=i*2)
            )
            for i in range(10)  # 10 transactions in 20 minutes
        ]
        
        velocity_analysis = analyzer.analyze_velocity(user_id, velocity_transactions)
        
        assert "transactions_per_hour" in velocity_analysis
        assert "velocity_score" in velocity_analysis
        assert "is_high_velocity" in velocity_analysis
        
        # Should detect high velocity
        assert velocity_analysis["is_high_velocity"] is True
        assert velocity_analysis["velocity_score"] > 0.7
    
    def test_network_analysis(self, analyzer):
        """Test transaction network analysis"""
        # Create connected transactions (same merchants, similar amounts)
        network_transactions = []
        
        # Group 1: Connected users
        for user_id in [1, 2, 3]:
            for i in range(5):
                txn = TestDataFactory.create_transaction(
                    user_id=user_id,
                    merchant_id="suspicious_merchant",
                    amount=100.00,  # Same amount
                    timestamp=datetime.utcnow() + timedelta(minutes=i)
                )
                network_transactions.append(txn)
        
        network_analysis = analyzer.analyze_transaction_network(network_transactions)
        
        assert "connected_users" in network_analysis
        assert "suspicious_patterns" in network_analysis
        assert "network_risk_score" in network_analysis
        
        # Should detect connected pattern
        assert len(network_analysis["connected_users"]) >= 3
        assert network_analysis["network_risk_score"] > 0.6


class TestFraudDetectionIntegration:
    """Integration tests for fraud detection system"""
    
    @pytest.fixture
    def client(self, test_app):
        """Create test client"""
        return TestClient(test_app)
    
    @pytest.fixture
    def authenticated_headers(self, client):
        """Get authenticated headers for API requests"""
        # Register and login user
        user_data = TestDataFactory.create_user()
        client.post("/auth/register", json=user_data)
        
        login_response = client.post("/auth/login", data={
            "username": user_data["email"],
            "password": user_data["password"]
        })
        
        token = login_response.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}
    
    def test_fraud_detection_api_endpoint(self, client, authenticated_headers):
        """Test fraud detection API endpoint"""
        transaction_data = {
            "amount": 500.00,
            "merchant_id": "merchant_test",
            "location": "New York, NY",
            "card_number": "****1234",
            "transaction_type": "purchase"
        }
        
        response = client.post(
            "/fraud/analyze",
            json=transaction_data,
            headers=authenticated_headers
        )
        
        assert response.status_code == 200
        
        result = response.json()
        assert "fraud_score" in result
        assert "risk_level" in result
        assert "decision" in result
        assert "analysis_details" in result
    
    def test_batch_fraud_analysis_endpoint(self, client, authenticated_headers):
        """Test batch fraud analysis endpoint"""
        transactions_data = {
            "transactions": [
                {
                    "id": f"txn_{i}",
                    "amount": 100.00 + i*50,
                    "merchant_id": f"merchant_{i}",
                    "location": "New York, NY"
                }
                for i in range(5)
            ]
        }
        
        response = client.post(
            "/fraud/analyze-batch",
            json=transactions_data,
            headers=authenticated_headers
        )
        
        assert response.status_code == 200
        
        results = response.json()
        assert "results" in results
        assert len(results["results"]) == 5
        
        for result in results["results"]:
            assert "transaction_id" in result
            assert "fraud_score" in result
    
    def test_fraud_alert_retrieval(self, client, authenticated_headers):
        """Test fraud alert retrieval"""
        response = client.get(
            "/fraud/alerts",
            headers=authenticated_headers
        )
        
        assert response.status_code == 200
        
        alerts = response.json()
        assert "alerts" in alerts
        assert "total_count" in alerts
        assert "page" in alerts
    
    def test_fraud_feedback_submission(self, client, authenticated_headers):
        """Test fraud feedback submission"""
        feedback_data = {
            "transaction_id": "txn_test_001",
            "is_fraud": False,
            "feedback_type": "false_positive",
            "comments": "This was a legitimate purchase"
        }
        
        response = client.post(
            "/fraud/feedback",
            json=feedback_data,
            headers=authenticated_headers
        )
        
        assert response.status_code == 200
        
        result = response.json()
        assert result["message"] == "Feedback submitted successfully"
    
    def test_end_to_end_fraud_detection_workflow(self, client, authenticated_headers):
        """Test complete fraud detection workflow"""
        # 1. Submit transaction for analysis
        transaction_data = {
            "amount": 1500.00,  # High amount
            "merchant_id": "unknown_merchant",
            "location": "Suspicious Location",
            "card_number": "****9999"
        }
        
        analysis_response = client.post(
            "/fraud/analyze",
            json=transaction_data,
            headers=authenticated_headers
        )
        
        assert analysis_response.status_code == 200
        analysis_result = analysis_response.json()
        
        # 2. If high fraud score, check for alerts
        if analysis_result["fraud_score"] > 0.8:
            alerts_response = client.get(
                "/fraud/alerts?severity=high",
                headers=authenticated_headers
            )
            
            assert alerts_response.status_code == 200
            alerts = alerts_response.json()
            
            # Should have generated an alert
            assert alerts["total_count"] > 0
        
        # 3. Submit feedback
        feedback_data = {
            "transaction_id": analysis_result.get("transaction_id", "test_txn"),
            "is_fraud": True,
            "feedback_type": "confirmed_fraud",
            "comments": "Confirmed fraudulent transaction"
        }
        
        feedback_response = client.post(
            "/fraud/feedback",
            json=feedback_data,
            headers=authenticated_headers
        )
        
        assert feedback_response.status_code == 200
    
    def test_fraud_detection_performance(self, client, authenticated_headers):
        """Test fraud detection system performance"""
        transaction_data = {
            "amount": 250.00,
            "merchant_id": "merchant_test",
            "location": "New York, NY"
        }
        
        # Test response time
        with PerformanceTimer() as timer:
            response = client.post(
                "/fraud/analyze",
                json=transaction_data,
                headers=authenticated_headers
            )
        
        assert response.status_code == 200
        assert timer.elapsed_ms < 1000  # Should complete within 1 second
        
        result = response.json()
        assert "processing_time" in result
        assert result["processing_time"] < 1.0  # Processing time under 1 second


if __name__ == "__main__":
    pytest.main([__file__, "-v"])