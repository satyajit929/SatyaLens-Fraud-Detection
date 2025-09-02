"""
Fraud Detection and Prevention Module

This module provides comprehensive fraud detection capabilities including:
- Real-time transaction monitoring
- Pattern analysis and anomaly detection
- Risk scoring and assessment
- Machine learning-based fraud prediction
- Rule-based fraud prevention
- Investigation and case management
"""

from .detector import FraudDetector, FraudPattern, FraudRule
from .analyzer import FraudAnalyzer, RiskAnalyzer, PatternAnalyzer
from .models import (
    FraudCase, FraudAlert, FraudRule as FraudRuleModel,
    RiskScore, TransactionAnalysis, FraudInvestigation
)
from .rules import RuleEngine, RuleType, RuleCondition, RuleAction
from .ml import MLFraudDetector, FraudPredictor, AnomalyDetector
from .scoring import RiskScorer, FraudScorer, BehaviorScorer
from .investigation import InvestigationManager, CaseManager, EvidenceCollector
from .prevention import PreventionEngine, BlockingService, AlertingService
from .reporting import FraudReporter, AnalyticsEngine, DashboardService
from .services import FraudService, MonitoringService as FraudMonitoringService

__version__ = "1.0.0"
__author__ = "Security Team"

# Export main classes and functions
__all__ = [
    # Core detection
    "FraudDetector",
    "FraudPattern", 
    "FraudRule",
    
    # Analysis
    "FraudAnalyzer",
    "RiskAnalyzer", 
    "PatternAnalyzer",
    
    # Database models
    "FraudCase",
    "FraudAlert",
    "FraudRuleModel",
    "RiskScore",
    "TransactionAnalysis", 
    "FraudInvestigation",
    
    # Rule engine
    "RuleEngine",
    "RuleType",
    "RuleCondition",
    "RuleAction",
    
    # Machine learning
    "MLFraudDetector",
    "FraudPredictor",
    "AnomalyDetector",
    
    # Scoring
    "RiskScorer",
    "FraudScorer", 
    "BehaviorScorer",
    
    # Investigation
    "InvestigationManager",
    "CaseManager",
    "EvidenceCollector",
    
    # Prevention
    "PreventionEngine",
    "BlockingService",
    "AlertingService",
    
    # Reporting
    "FraudReporter",
    "AnalyticsEngine",
    "DashboardService",
    
    # Services
    "FraudService",
    "FraudMonitoringService"
]

# Module configuration
DEFAULT_CONFIG = {
    "detection": {
        "enabled": True,
        "real_time": True,
        "batch_processing": True,
        "ml_enabled": True,
        "rule_based": True
    },
    "scoring": {
        "risk_threshold": 0.7,
        "fraud_threshold": 0.8,
        "behavior_threshold": 0.6
    },
    "prevention": {
        "auto_block": False,
        "alert_threshold": 0.75,
        "investigation_threshold": 0.85
    },
    "ml": {
        "model_update_frequency": "daily",
        "training_data_days": 90,
        "feature_engineering": True
    }
}

# Initialize fraud detection system
def initialize_fraud_system(config=None):
    """Initialize the fraud detection system with configuration"""
    if config is None:
        config = DEFAULT_CONFIG
    
    # Initialize core components
    fraud_service = FraudService(config)
    return fraud_service

# Quick access functions
def detect_fraud(transaction_data, user_context=None):
    """Quick fraud detection for a single transaction"""
    detector = FraudDetector()
    return detector.detect(transaction_data, user_context)

def calculate_risk_score(user_id, transaction_data):
    """Calculate risk score for a transaction"""
    scorer = RiskScorer()
    return scorer.calculate_score(user_id, transaction_data)

def analyze_patterns(user_id, timeframe_days=30):
    """Analyze fraud patterns for a user"""
    analyzer = PatternAnalyzer()
    return analyzer.analyze_user_patterns(user_id, timeframe_days)