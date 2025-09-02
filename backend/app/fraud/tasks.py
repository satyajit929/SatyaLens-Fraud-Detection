"""
Fraud Detection Background Tasks Module

This module contains Celery tasks for background fraud detection processing,
batch analysis, model training, and scheduled maintenance operations.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from celery import Celery, Task
from celery.schedules import crontab
import pandas as pd
import numpy as np
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc, func
import json
import pickle
from redis import Redis

from ..database import (
    get_db, Transaction, User, FraudCase, FraudAlert, 
    FraudRule, RiskScore, TransactionAnalysis
)
from ..config import settings
from .detector import FraudDetector, TransactionContext
from .patterns import PatternDetectionEngine
from .models import FraudType, DetectionMethod
from .ml import MLFraudDetector
from .rules import RuleEngine
from .notifications import FraudNotificationService

logger = logging.getLogger(__name__)

# Initialize Celery app
celery_app = Celery(
    'fraud_tasks',
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND
)

# Celery configuration
celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,  # 30 minutes
    task_soft_time_limit=25 * 60,  # 25 minutes
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    worker_disable_rate_limits=False,
    task_compression='gzip',
    result_compression='gzip',
    result_expires=3600,  # 1 hour
)

# Task routing
celery_app.conf.task_routes = {
    'fraud_tasks.analyze_transaction': {'queue': 'fraud_realtime'},
    'fraud_tasks.batch_analyze_transactions': {'queue': 'fraud_batch'},
    'fraud_tasks.retrain_ml_models': {'queue': 'fraud_ml'},
    'fraud_tasks.generate_fraud_report': {'queue': 'fraud_reports'},
    'fraud_tasks.cleanup_old_data': {'queue': 'fraud_maintenance'},
}

class FraudTask(Task):
    """Base task class for fraud detection tasks"""
    
    def __init__(self):
        self.fraud_detector = None
        self.pattern_engine = None
        self.notification_service = None
        self.redis = None
    
    def __call__(self, *args, **kwargs):
        if not self.fraud_detector:
            self.redis = Redis.from_url(settings.REDIS_URL)
            self.fraud_detector = FraudDetector(self.redis)
            self.pattern_engine = PatternDetectionEngine(self.redis)
            self.notification_service = FraudNotificationService()
        
        return super().__call__(*args, **kwargs)

@celery_app.task(bind=True, base=FraudTask, name='fraud_tasks.analyze_transaction')
def analyze_transaction(self, transaction_id: str, priority: str = 'normal') -> Dict[str, Any]:
    """
    Analyze a single transaction for fraud
    
    Args:
        transaction_id: ID of transaction to analyze
        priority: Priority level (low, normal, high, critical)
        
    Returns:
        Dict containing analysis results
    """
    try:
        logger.info(f"Starting fraud analysis for transaction {transaction_id}")
        
        # Get transaction data
        db = next(get_db())
        transaction = db.query(Transaction).filter(Transaction.id == transaction_id).first()
        
        if not transaction:
            logger.error(f"Transaction {transaction_id} not found")
            return {"error": "Transaction not found", "transaction_id": transaction_id}
        
        # Create transaction context
        context = TransactionContext(
            user_id=transaction.user_id,
            transaction_id=transaction_id,
            amount=float(transaction.amount),
            currency=transaction.currency,
            merchant=transaction.merchant,
            location={
                "latitude": transaction.latitude,
                "longitude": transaction.longitude,
                "country": transaction.country,
                "city": transaction.city
            } if transaction.latitude else None,
            device_info=json.loads(transaction.device_info) if transaction.device_info else None,
            ip_address=transaction.ip_address,
            timestamp=transaction.created_at,
            payment_method=transaction.payment_method,
            user_history=None,  # Will be fetched by detector
            session_data=json.loads(transaction.session_data) if transaction.session_data else None
        )
        
        # Run fraud detection
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            detection_result = loop.run_until_complete(
                self.fraud_detector.detect_fraud(context)
            )
        finally:
            loop.close()
        
        # Handle high-risk results
        if detection_result.is_fraud or detection_result.risk_score > 0.8:
            # Send immediate alert for high-risk transactions
            alert_task.delay(
                transaction_id=transaction_id,
                fraud_type=detection_result.fraud_types[0].value if detection_result.fraud_types else "unknown",
                risk_score=detection_result.risk_score,
                priority="high" if detection_result.risk_score > 0.9 else "medium"
            )
            
            # Update transaction status if fraud detected
            if detection_result.is_fraud:
                transaction.status = "blocked"
                transaction.fraud_score = detection_result.risk_score
                db.commit()
        
        result = {
            "transaction_id": transaction_id,
            "is_fraud": detection_result.is_fraud,
            "risk_score": detection_result.risk_score,
            "fraud_probability": detection_result.fraud_probability,
            "fraud_types": [ft.value for ft in detection_result.fraud_types],
            "recommended_action": detection_result.recommended_action,
            "processing_time_ms": detection_result.processing_time_ms,
            "patterns_detected": len(detection_result.patterns),
            "analysis_timestamp": datetime.utcnow().isoformat()
        }
        
        logger.info(f"Fraud analysis completed for transaction {transaction_id}: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Fraud analysis failed for transaction {transaction_id}: {e}")
        self.retry(countdown=60, max_retries=3)

@celery_app.task(bind=True, base=FraudTask, name='fraud_tasks.batch_analyze_transactions')
def batch_analyze_transactions(self, transaction_ids: List[str], batch_size: int = 100) -> Dict[str, Any]:
    """
    Analyze multiple transactions in batch
    
    Args:
        transaction_ids: List of transaction IDs to analyze
        batch_size: Number of transactions to process in each batch
        
    Returns:
        Dict containing batch analysis results
    """
    try:
        logger.info(f"Starting batch fraud analysis for {len(transaction_ids)} transactions")
        
        results = {
            "total_transactions": len(transaction_ids),
            "processed": 0,
            "fraud_detected": 0,
            "high_risk": 0,
            "errors": 0,
            "batch_results": []
        }
        
        # Process in batches
        for i in range(0, len(transaction_ids), batch_size):
            batch = transaction_ids[i:i + batch_size]
            
            # Process batch transactions
            batch_tasks = []
            for txn_id in batch:
                task = analyze_transaction.delay(txn_id, priority='batch')
                batch_tasks.append((txn_id, task))
            
            # Collect batch results
            batch_results = []
            for txn_id, task in batch_tasks:
                try:
                    result = task.get(timeout=300)  # 5 minute timeout
                    batch_results.append(result)
                    
                    results["processed"] += 1
                    
                    if result.get("is_fraud"):
                        results["fraud_detected"] += 1
                    
                    if result.get("risk_score", 0) > 0.7:
                        results["high_risk"] += 1
                        
                except Exception as e:
                    logger.error(f"Batch analysis failed for transaction {txn_id}: {e}")
                    results["errors"] += 1
            
            results["batch_results"].extend(batch_results)
            
            # Update progress
            progress = (i + len(batch)) / len(transaction_ids) * 100
            self.update_state(
                state='PROGRESS',
                meta={'progress': progress, 'processed': results["processed"]}
            )
        
        logger.info(f"Batch fraud analysis completed: {results}")
        return results
        
    except Exception as e:
        logger.error(f"Batch fraud analysis failed: {e}")
        raise

@celery_app.task(bind=True, base=FraudTask, name='fraud_tasks.pattern_analysis')
def pattern_analysis(self, user_id: int, lookback_days: int = 7) -> Dict[str, Any]:
    """
    Analyze patterns for a specific user
    
    Args:
        user_id: User ID to analyze
        lookback_days: Number of days to look back
        
    Returns:
        Dict containing pattern analysis results
    """
    try:
        logger.info(f"Starting pattern analysis for user {user_id}")
        
        # Get user's recent transactions
        db = next(get_db())
        cutoff_date = datetime.utcnow() - timedelta(days=lookback_days)
        
        transactions = db.query(Transaction).filter(
            Transaction.user_id == user_id,
            Transaction.created_at >= cutoff_date
        ).order_by(Transaction.created_at.desc()).all()
        
        if not transactions:
            return {"user_id": user_id, "patterns": [], "message": "No recent transactions"}
        
        # Analyze patterns for each transaction
        all_patterns = []
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            for transaction in transactions:
                transaction_data = {
                    "amount": float(transaction.amount),
                    "merchant": transaction.merchant,
                    "country": transaction.country,
                    "device_fingerprint": transaction.device_fingerprint,
                    "ip_address": transaction.ip_address,
                    "timestamp": transaction.created_at
                }
                
                patterns = loop.run_until_complete(
                    self.pattern_engine.detect_all_patterns(user_id, transaction_data)
                )
                
                for pattern in patterns:
                    all_patterns.append({
                        "transaction_id": transaction.id,
                        "pattern_type": pattern.pattern_type.value,
                        "confidence": pattern.confidence,
                        "risk_score": pattern.risk_score,
                        "evidence": pattern.evidence,
                        "detected_at": pattern.time_window[1].isoformat()
                    })
        finally:
            loop.close()
        
        # Aggregate pattern statistics
        pattern_stats = {}
        for pattern in all_patterns:
            pattern_type = pattern["pattern_type"]
            if pattern_type not in pattern_stats:
                pattern_stats[pattern_type] = {
                    "count": 0,
                    "avg_risk_score": 0,
                    "max_risk_score": 0
                }
            
            pattern_stats[pattern_type]["count"] += 1
            pattern_stats[pattern_type]["max_risk_score"] = max(
                pattern_stats[pattern_type]["max_risk_score"],
                pattern["risk_score"]
            )
        
        # Calculate average risk scores
        for stats in pattern_stats.values():
            if stats["count"] > 0:
                stats["avg_risk_score"] = sum(
                    p["risk_score"] for p in all_patterns 
                    if p["pattern_type"] in pattern_stats
                ) / stats["count"]
        
        result = {
            "user_id": user_id,
            "analysis_period_days": lookback_days,
            "total_transactions": len(transactions),
            "patterns_detected": len(all_patterns),
            "pattern_statistics": pattern_stats,
            "high_risk_patterns": [p for p in all_patterns if p["risk_score"] > 0.7],
            "analysis_timestamp": datetime.utcnow().isoformat()
        }
        
        logger.info(f"Pattern analysis completed for user {user_id}: {len(all_patterns)} patterns detected")
        return result
        
    except Exception as e:
        logger.error(f"Pattern analysis failed for user {user_id}: {e}")
        raise

@celery_app.task(bind=True, base=FraudTask, name='fraud_tasks.alert')
def alert(self, transaction_id: str, fraud_type: str, risk_score: float, priority: str = 'medium') -> Dict[str, Any]:
    """
    Send fraud alert
    
    Args:
        transaction_id: Transaction ID
        fraud_type: Type of fraud detected
        risk_score: Risk score
        priority: Alert priority
        
    Returns:
        Dict containing alert result
    """
    try:
        logger.info(f"Sending fraud alert for transaction {transaction_id}")
        
        # Get transaction and user details
        db = next(get_db())
        transaction = db.query(Transaction).filter(Transaction.id == transaction_id).first()
        
        if not transaction:
            return {"error": "Transaction not found"}
        
        user = db.query(User).filter(User.id == transaction.user_id).first()
        
        # Create fraud alert record
        fraud_alert = FraudAlert(
            transaction_id=transaction_id,
            user_id=transaction.user_id,
            fraud_type=fraud_type,
            risk_score=risk_score,
            priority=priority,
            status='open',
            created_at=datetime.utcnow(),
            metadata={
                "amount": float(transaction.amount),
                "merchant": transaction.merchant,
                "country": transaction.country
            }
        )
        
        db.add(fraud_alert)
        db.commit()
        
        # Send notifications based on priority
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            if priority in ['high', 'critical']:
                # Send immediate notifications
                loop.run_until_complete(
                    self.notification_service.send_immediate_alert(
                        alert_id=fraud_alert.id,
                        transaction_id=transaction_id,
                        user_email=user.email if user else None,
                        fraud_type=fraud_type,
                        risk_score=risk_score
                    )
                )
            else:
                # Queue for batch notification
                loop.run_until_complete(
                    self.notification_service.queue_alert(fraud_alert.id)
                )
        finally:
            loop.close()
        
        result = {
            "alert_id": fraud_alert.id,
            "transaction_id": transaction_id,
            "fraud_type": fraud_type,
            "risk_score": risk_score,
            "priority": priority,
            "status": "sent",
            "timestamp": datetime.utcnow().isoformat()
        }
        
        logger.info(f"Fraud alert sent: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Failed to send fraud alert for transaction {transaction_id}: {e}")
        raise

@celery_app.task(bind=True, base=FraudTask, name='fraud_tasks.retrain_ml_models')
def retrain_ml_models(self, model_type: str = 'all') -> Dict[str, Any]:
    """
    Retrain machine learning fraud detection models
    
    Args:
        model_type: Type of model to retrain ('all', 'fraud_classifier', 'anomaly_detector')
        
    Returns:
        Dict containing retraining results
    """
    try:
        logger.info(f"Starting ML model retraining: {model_type}")
        
        # Get training data
        db = next(get_db())
        cutoff_date = datetime.utcnow() - timedelta(days=90)  # Last 90 days
        
        # Get transactions with fraud labels
        transactions = db.query(Transaction).join(
            FraudCase, Transaction.id == FraudCase.transaction_id, isouter=True
        ).filter(
            Transaction.created_at >= cutoff_date
        ).all()
        
        if len(transactions) < 1000:  # Minimum training data
            return {"error": "Insufficient training data", "transaction_count": len(transactions)}
        
        # Prepare training dataset
        training_data = []
        for txn in transactions:
            fraud_case = next((fc for fc in txn.fraud_cases), None)
            
            features = {
                "amount": float(txn.amount),
                "hour": txn.created_at.hour,
                "day_of_week": txn.created_at.weekday(),
                "merchant_category": txn.merchant_category or "unknown",
                "country": txn.country or "unknown",
                "payment_method": txn.payment_method or "unknown",
                "is_fraud": 1 if fraud_case else 0
            }
            training_data.append(features)
        
        df = pd.DataFrame(training_data)
        
        # Initialize ML detector
        ml_detector = MLFraudDetector()
        
        # Retrain models
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            success = loop.run_until_complete(ml_detector.retrain_model(df))
        finally:
            loop.close()
        
        if success:
            # Update model version in Redis
            self.redis.set("ml_model_version", datetime.utcnow().isoformat())
            self.redis.set("ml_model_last_trained", datetime.utcnow().isoformat())
            
            result = {
                "status": "success",
                "model_type": model_type,
                "training_samples": len(df),
                "fraud_samples": df['is_fraud'].sum(),
                "training_timestamp": datetime.utcnow().isoformat()
            }
        else:
            result = {
                "status": "failed",
                "model_type": model_type,
                "error": "Model training failed"
            }
        
        logger.info(f"ML model retraining completed: {result}")
        return result
        
    except Exception as e:
        logger.error(f"ML model retraining failed: {e}")
        raise

@celery_app.task(bind=True, base=FraudTask, name='fraud_tasks.generate_fraud_report')
def generate_fraud_report(self, report_type: str, start_date: str, end_date: str) -> Dict[str, Any]:
    """
    Generate fraud detection report
    
    Args:
        report_type: Type of report ('summary', 'detailed', 'patterns')
        start_date: Start date (ISO format)
        end_date: End date (ISO format)
        
    Returns:
        Dict containing report data
    """
    try:
        logger.info(f"Generating fraud report: {report_type} from {start_date} to {end_date}")
        
        start_dt = datetime.fromisoformat(start_date)
        end_dt = datetime.fromisoformat(end_date)
        
        db = next(get_db())
        
        # Get fraud cases in date range
        fraud_cases = db.query(FraudCase).filter(
            FraudCase.created_at >= start_dt,
            FraudCase.created_at <= end_dt
        ).all()
        
        # Get all transactions in date range
        transactions = db.query(Transaction).filter(
            Transaction.created_at >= start_dt,
            Transaction.created_at <= end_dt
        ).all()
        
        # Calculate basic statistics
        total_transactions = len(transactions)
        total_fraud_cases = len(fraud_cases)
        fraud_rate = (total_fraud_cases / total_transactions * 100) if total_transactions > 0 else 0
        
        # Calculate financial impact
        fraud_amount = sum(float(fc.transaction.amount) for fc in fraud_cases if fc.transaction)
        total_amount = sum(float(txn.amount) for txn in transactions)
        
        # Fraud type distribution
        fraud_type_counts = {}
        for case in fraud_cases:
            fraud_type = case.fraud_type
            fraud_type_counts[fraud_type] = fraud_type_counts.get(fraud_type, 0) + 1
        
        # Detection method effectiveness
        detection_methods = {}
        for case in fraud_cases:
            method = case.detection_method
            detection_methods[method] = detection_methods.get(method, 0) + 1
        
        # Daily fraud trend
        daily_fraud = {}
        for case in fraud_cases:
            date_key = case.created_at.date().isoformat()
            daily_fraud[date_key] = daily_fraud.get(date_key, 0) + 1
        
        report = {
            "report_type": report_type,
            "period": {
                "start_date": start_date,
                "end_date": end_date,
                "days": (end_dt - start_dt).days
            },
            "summary": {
                "total_transactions": total_transactions,
                "total_fraud_cases": total_fraud_cases,
                "fraud_rate_percent": round(fraud_rate, 2),
                "total_amount": total_amount,
                "fraud_amount": fraud_amount,
                "fraud_amount_percent": round((fraud_amount / total_amount * 100) if total_amount > 0 else 0, 2)
            },
            "fraud_types": fraud_type_counts,
            "detection_methods": detection_methods,
            "daily_trend": daily_fraud,
            "generated_at": datetime.utcnow().isoformat()
        }
        
        # Add detailed information for detailed reports
        if report_type == 'detailed':
            report["detailed_cases"] = [
                {
                    "id": case.id,
                    "transaction_id": case.transaction_id,
                    "fraud_type": case.fraud_type,
                    "risk_score": case.risk_score,
                    "amount": float(case.transaction.amount) if case.transaction else 0,
                    "status": case.status,
                    "created_at": case.created_at.isoformat()
                }
                for case in fraud_cases[:100]  # Limit to 100 for performance
            ]
        
        logger.info(f"Fraud report generated: {report['summary']}")
        return report
        
    except Exception as e:
        logger.error(f"Fraud report generation failed: {e}")
        raise

@celery_app.task(bind=True, base=FraudTask, name='fraud_tasks.update_risk_profiles')
def update_risk_profiles(self, user_ids: Optional[List[int]] = None) -> Dict[str, Any]:
    """
    Update user risk profiles
    
    Args:
        user_ids: Specific user IDs to update (None for all users)
        
    Returns:
        Dict containing update results
    """
    try:
        logger.info(f"Updating risk profiles for {len(user_ids) if user_ids else 'all'} users")
        
        db = next(get_db())
        
        # Get users to update
        if user_ids:
            users = db.query(User).filter(User.id.in_(user_ids)).all()
        else:
            # Update users with recent activity
            cutoff_date = datetime.utcnow() - timedelta(days=30)
            users = db.query(User).join(Transaction).filter(
                Transaction.created_at >= cutoff_date
            ).distinct().all()
        
        updated_count = 0
        errors = 0
        
        for user in users:
            try:
                # Calculate user risk score
                user_transactions = db.query(Transaction).filter(
                    Transaction.user_id == user.id,
                    Transaction.created_at >= datetime.utcnow() - timedelta(days=90)
                ).all()
                
                if not user_transactions:
                    continue
                
                # Get fraud cases for this user
                fraud_cases = db.query(FraudCase).join(Transaction).filter(
                    Transaction.user_id == user.id,
                    FraudCase.created_at >= datetime.utcnow() - timedelta(days=90)
                ).all()
                
                # Calculate risk factors
                total_transactions = len(user_transactions)
                fraud_count = len(fraud_cases)
                fraud_rate = fraud_count / total_transactions if total_transactions > 0 else 0
                
                # Calculate average transaction amount
                avg_amount = np.mean([float(txn.amount) for txn in user_transactions])
                
                # Calculate risk score (0-1)
                risk_score = min(fraud_rate * 2 + (avg_amount / 10000) * 0.1, 1.0)
                
                # Update user risk profile in Redis
                risk_key = f"user_risk:{user.id}"
                self.redis.setex(risk_key, 86400, str(risk_score))  # 24 hour TTL
                
                updated_count += 1
                
            except Exception as e:
                logger.error(f"Failed to update risk profile for user {user.id}: {e}")
                errors += 1
        
        result = {
            "users_processed": len(users),
            "profiles_updated": updated_count,
            "errors": errors,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        logger.info(f"Risk profile update completed: {result}")
        return result
        
    except Exception as e:
        logger.error(f"Risk profile update failed: {e}")
        raise

@celery_app.task(bind=True, base=FraudTask, name='fraud_tasks.cleanup_old_data')
def cleanup_old_data(self, retention_days: int = 365) -> Dict[str, Any]:
    """
    Clean up old fraud detection data
    
    Args:
        retention_days: Number of days to retain data
        
    Returns:
        Dict containing cleanup results
    """
    try:
        logger.info(f"Starting cleanup of data older than {retention_days} days")
        
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        db = next(get_db())
        
        cleanup_results = {}
        
        # Clean up old fraud cases
        old_fraud_cases = db.query(FraudCase).filter(
            FraudCase.created_at < cutoff_date
        ).count()
        
        db.query(FraudCase).filter(
            FraudCase.created_at < cutoff_date
        ).delete()
        
        cleanup_results["fraud_cases_deleted"] = old_fraud_cases
        
        # Clean up old risk scores
        old_risk_scores = db.query(RiskScore).filter(
            RiskScore.calculated_at < cutoff_date
        ).count()
        
        db.query(RiskScore).filter(
            RiskScore.calculated_at < cutoff_date
        ).delete()
        
        cleanup_results["risk_scores_deleted"] = old_risk_scores
        
        # Clean up old fraud alerts
        old_alerts = db.query(FraudAlert).filter(
            FraudAlert.created_at < cutoff_date
        ).count()
        
        db.query(FraudAlert).filter(
            FraudAlert.created_at < cutoff_date
        ).delete()
        
        cleanup_results["alerts_deleted"] = old_alerts
        
        db.commit()
        
        # Clean up Redis cache entries
        redis_keys_deleted = 0
        for key in self.redis.scan_iter(match="user_stats:*"):
            # Check if key is old (this is approximate)
            if self.redis.ttl(key) < 0:  # No TTL set, likely old
                self.redis.delete(key)
                redis_keys_deleted += 1
        
        cleanup_results["redis_keys_deleted"] = redis_keys_deleted
        cleanup_results["retention_days"] = retention_days
        cleanup_results["cutoff_date"] = cutoff_date.isoformat()
        cleanup_results["cleanup_timestamp"] = datetime.utcnow().isoformat()
        
        logger.info(f"Data cleanup completed: {cleanup_results}")
        return cleanup_results
        
    except Exception as e:
        logger.error(f"Data cleanup failed: {e}")
        raise

# Periodic tasks
@celery_app.task(bind=True, base=FraudTask, name='fraud_tasks.daily_fraud_summary')
def daily_fraud_summary(self):
    """Generate daily fraud summary report"""
    try:
        yesterday = datetime.utcnow() - timedelta(days=1)
        start_date = yesterday.replace(hour=0, minute=0, second=0, microsecond=0)
        end_date = yesterday.replace(hour=23, minute=59, second=59, microsecond=999999)
        
        # Generate report
        report = generate_fraud_report.delay(
            report_type='summary',
            start_date=start_date.isoformat(),
            end_date=end_date.isoformat()
        ).get()
        
        # Send summary to stakeholders
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            loop.run_until_complete(
                self.notification_service.send_daily_summary(report)
            )
        finally:
            loop.close()
        
        return {"status": "success", "report": report}
        
    except Exception as e:
        logger.error(f"Daily fraud summary failed: {e}")
        raise

@celery_app.task(bind=True, base=FraudTask, name='fraud_tasks.weekly_model_retrain')
def weekly_model_retrain(self):
    """Weekly ML model retraining"""
    try:
        result = retrain_ml_models.delay('all').get()
        return result
    except Exception as e:
        logger.error(f"Weekly model retrain failed: {e}")
        raise

# Celery beat schedule for periodic tasks
celery_app.conf.beat_schedule = {
    'daily-fraud-summary': {
        'task': 'fraud_tasks.daily_fraud_summary',
        'schedule': crontab(hour=1, minute=0),  # Daily at 1 AM
    },
    'weekly-model-retrain': {
        'task': 'fraud_tasks.weekly_model_retrain',
        'schedule': crontab(hour=2, minute=0, day_of_week=1),  # Weekly on Monday at 2 AM
    },
    'update-risk-profiles': {
        'task': 'fraud_tasks.update_risk_profiles',
        'schedule': crontab(hour=3, minute=0),  # Daily at 3 AM
    },
    'cleanup-old-data': {
        'task': 'fraud_tasks.cleanup_old_data',
        'schedule': crontab(hour=4, minute=0, day_of_week=0),  # Weekly on Sunday at 4 AM
    },
}

# Task monitoring and health checks
@celery_app.task(name='fraud_tasks.health_check')
def health_check() -> Dict[str, Any]:
    """Health check for fraud detection system"""
    try:
        # Check database connectivity
        db = next(get_db())
        db.execute("SELECT 1")
        
        # Check Redis connectivity
        redis = Redis.from_url(settings.REDIS_URL)
        redis.ping()
        
        # Check recent task execution
        inspect = celery_app.control.inspect()
        active_tasks = inspect.active()
        
        return {
            "status": "healthy",
            "database": "connected",
            "redis": "connected",
            "active_tasks": len(active_tasks) if active_tasks else 0,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }

# Task result callbacks
@celery_app.task(bind=True, name='fraud_tasks.task_success_callback')
def task_success_callback(self, task_id: str, result: Any, traceback: str):
    """Callback for successful task completion"""
    logger.info(f"Task {task_id} completed successfully")

@celery_app.task(bind=True, name='fraud_tasks.task_failure_callback')
def task_failure_callback(self, task_id: str, error: str, traceback: str):
    """Callback for failed task"""
    logger.error(f"Task {task_id} failed: {error}")
    
    # Send alert for critical task failures
    if any(critical_task in task_id for critical_task in ['analyze_transaction', 'alert']):
        # Send notification about task failure
        pass

# Export task functions for external use
__all__ = [
    'analyze_transaction',
    'batch_analyze_transactions',
    'pattern_analysis',
    'alert',
    'retrain_ml_models',
    'generate_fraud_report',
    'update_risk_profiles',
    'cleanup_old_data',
    'daily_fraud_summary',
    'weekly_model_retrain',
    'health_check'
]

