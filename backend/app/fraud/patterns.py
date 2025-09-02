"""
Fraud Pattern Detection Module

This module contains sophisticated pattern detection algorithms for identifying
various types of fraud patterns in transaction data and user behavior.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Tuple, Set
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, asdict
import json
import hashlib
import numpy as np
import pandas as pd
from collections import defaultdict, deque
from geopy.distance import geodesic
import user_agents
from redis import Redis

from ..database import get_db, Transaction, User, FraudCase
from ..config import settings
from .models import FraudPattern, FraudType, DetectionMethod

logger = logging.getLogger(__name__)

class PatternType(str, Enum):
    VELOCITY_BURST = "velocity_burst"
    VELOCITY_SUSTAINED = "velocity_sustained"
    AMOUNT_ESCALATION = "amount_escalation"
    AMOUNT_ROUND_NUMBERS = "amount_round_numbers"
    LOCATION_IMPOSSIBLE_TRAVEL = "location_impossible_travel"
    LOCATION_HIGH_RISK_COUNTRY = "location_high_risk_country"
    LOCATION_RAPID_CHANGES = "location_rapid_changes"
    DEVICE_MULTIPLE_ACCOUNTS = "device_multiple_accounts"
    DEVICE_SUSPICIOUS_FINGERPRINT = "device_suspicious_fingerprint"
    BEHAVIORAL_TIME_ANOMALY = "behavioral_time_anomaly"
    BEHAVIORAL_MERCHANT_ANOMALY = "behavioral_merchant_anomaly"
    NETWORK_COORDINATED_ATTACK = "network_coordinated_attack"
    NETWORK_ACCOUNT_ENUMERATION = "network_account_enumeration"
    PAYMENT_METHOD_TESTING = "payment_method_testing"
    CHARGEBACK_PATTERN = "chargeback_pattern"

@dataclass
class PatternMatch:
    """Represents a detected pattern match"""
    pattern_type: PatternType
    confidence: float
    risk_score: float
    evidence: Dict[str, Any]
    affected_entities: List[str]
    time_window: Tuple[datetime, datetime]
    metadata: Dict[str, Any]

class BasePatternDetector:
    """Base class for all pattern detectors"""
    
    def __init__(self, redis_client: Redis):
        self.redis = redis_client
        self.pattern_cache_ttl = 3600  # 1 hour
        
    async def detect(self, context: Any) -> List[PatternMatch]:
        """Detect patterns - to be implemented by subclasses"""
        raise NotImplementedError
        
    def _calculate_confidence(self, evidence: Dict[str, Any]) -> float:
        """Calculate confidence score based on evidence strength"""
        # Base implementation - can be overridden
        evidence_count = len(evidence)
        return min(evidence_count * 0.2, 1.0)
        
    def _calculate_risk_score(self, pattern_type: PatternType, confidence: float) -> float:
        """Calculate risk score based on pattern type and confidence"""
        # Risk multipliers for different pattern types
        risk_multipliers = {
            PatternType.VELOCITY_BURST: 0.8,
            PatternType.VELOCITY_SUSTAINED: 0.9,
            PatternType.AMOUNT_ESCALATION: 0.7,
            PatternType.LOCATION_IMPOSSIBLE_TRAVEL: 0.95,
            PatternType.LOCATION_HIGH_RISK_COUNTRY: 0.6,
            PatternType.DEVICE_MULTIPLE_ACCOUNTS: 0.85,
            PatternType.NETWORK_COORDINATED_ATTACK: 0.95,
            PatternType.PAYMENT_METHOD_TESTING: 0.8,
            PatternType.CHARGEBACK_PATTERN: 0.9
        }
        
        multiplier = risk_multipliers.get(pattern_type, 0.5)
        return confidence * multiplier

class VelocityPatternDetector(BasePatternDetector):
    """Detects velocity-based fraud patterns"""
    
    def __init__(self, redis_client: Redis):
        super().__init__(redis_client)
        self.burst_threshold = 10  # transactions
        self.burst_window = 300    # 5 minutes
        self.sustained_threshold = 50  # transactions
        self.sustained_window = 3600   # 1 hour
        
    async def detect(self, user_id: int, transaction_data: Dict[str, Any]) -> List[PatternMatch]:
        """Detect velocity patterns for a user"""
        patterns = []
        
        # Get recent transaction history
        recent_transactions = await self._get_recent_transactions(user_id)
        
        # Check for velocity burst
        burst_pattern = await self._detect_velocity_burst(user_id, recent_transactions)
        if burst_pattern:
            patterns.append(burst_pattern)
            
        # Check for sustained velocity
        sustained_pattern = await self._detect_sustained_velocity(user_id, recent_transactions)
        if sustained_pattern:
            patterns.append(sustained_pattern)
            
        return patterns
    
    async def _get_recent_transactions(self, user_id: int) -> List[Dict[str, Any]]:
        """Get recent transactions for velocity analysis"""
        cache_key = f"recent_txns:{user_id}"
        cached_data = self.redis.get(cache_key)
        
        if cached_data:
            return json.loads(cached_data)
        
        # Query database
        db = next(get_db())
        cutoff_time = datetime.utcnow() - timedelta(hours=2)
        
        transactions = db.query(Transaction).filter(
            Transaction.user_id == user_id,
            Transaction.created_at >= cutoff_time
        ).order_by(Transaction.created_at.desc()).all()
        
        txn_data = [
            {
                "id": txn.id,
                "amount": float(txn.amount),
                "created_at": txn.created_at.isoformat(),
                "merchant": txn.merchant,
                "status": txn.status
            }
            for txn in transactions
        ]
        
        # Cache for 5 minutes
        self.redis.setex(cache_key, 300, json.dumps(txn_data))
        
        return txn_data
    
    async def _detect_velocity_burst(self, user_id: int, transactions: List[Dict[str, Any]]) -> Optional[PatternMatch]:
        """Detect sudden burst in transaction velocity"""
        if len(transactions) < self.burst_threshold:
            return None
            
        now = datetime.utcnow()
        burst_cutoff = now - timedelta(seconds=self.burst_window)
        
        # Count transactions in burst window
        burst_transactions = [
            txn for txn in transactions
            if datetime.fromisoformat(txn["created_at"]) >= burst_cutoff
        ]
        
        if len(burst_transactions) >= self.burst_threshold:
            evidence = {
                "transaction_count": len(burst_transactions),
                "time_window_seconds": self.burst_window,
                "threshold": self.burst_threshold,
                "transactions": burst_transactions[:5]  # Sample
            }
            
            confidence = min(len(burst_transactions) / (self.burst_threshold * 2), 1.0)
            risk_score = self._calculate_risk_score(PatternType.VELOCITY_BURST, confidence)
            
            return PatternMatch(
                pattern_type=PatternType.VELOCITY_BURST,
                confidence=confidence,
                risk_score=risk_score,
                evidence=evidence,
                affected_entities=[str(user_id)],
                time_window=(burst_cutoff, now),
                metadata={"detector": "velocity", "user_id": user_id}
            )
        
        return None
    
    async def _detect_sustained_velocity(self, user_id: int, transactions: List[Dict[str, Any]]) -> Optional[PatternMatch]:
        """Detect sustained high velocity pattern"""
        if len(transactions) < self.sustained_threshold:
            return None
            
        now = datetime.utcnow()
        sustained_cutoff = now - timedelta(seconds=self.sustained_window)
        
        # Count transactions in sustained window
        sustained_transactions = [
            txn for txn in transactions
            if datetime.fromisoformat(txn["created_at"]) >= sustained_cutoff
        ]
        
        if len(sustained_transactions) >= self.sustained_threshold:
            evidence = {
                "transaction_count": len(sustained_transactions),
                "time_window_seconds": self.sustained_window,
                "threshold": self.sustained_threshold,
                "average_interval": self.sustained_window / len(sustained_transactions)
            }
            
            confidence = min(len(sustained_transactions) / (self.sustained_threshold * 1.5), 1.0)
            risk_score = self._calculate_risk_score(PatternType.VELOCITY_SUSTAINED, confidence)
            
            return PatternMatch(
                pattern_type=PatternType.VELOCITY_SUSTAINED,
                confidence=confidence,
                risk_score=risk_score,
                evidence=evidence,
                affected_entities=[str(user_id)],
                time_window=(sustained_cutoff, now),
                metadata={"detector": "velocity", "user_id": user_id}
            )
        
        return None

class AmountPatternDetector(BasePatternDetector):
    """Detects amount-based fraud patterns"""
    
    def __init__(self, redis_client: Redis):
        super().__init__(redis_client)
        self.escalation_factor = 2.0  # 2x increase threshold
        self.round_number_threshold = 0.7  # 70% round numbers
        
    async def detect(self, user_id: int, transaction_data: Dict[str, Any]) -> List[PatternMatch]:
        """Detect amount-based patterns"""
        patterns = []
        
        # Get user's transaction history
        transaction_history = await self._get_transaction_history(user_id)
        
        # Check for amount escalation
        escalation_pattern = await self._detect_amount_escalation(user_id, transaction_history)
        if escalation_pattern:
            patterns.append(escalation_pattern)
            
        # Check for round number pattern
        round_number_pattern = await self._detect_round_numbers(user_id, transaction_history)
        if round_number_pattern:
            patterns.append(round_number_pattern)
            
        return patterns
    
    async def _get_transaction_history(self, user_id: int, days: int = 7) -> List[Dict[str, Any]]:
        """Get transaction history for amount analysis"""
        db = next(get_db())
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        transactions = db.query(Transaction).filter(
            Transaction.user_id == user_id,
            Transaction.created_at >= cutoff_date,
            Transaction.status == "completed"
        ).order_by(Transaction.created_at.asc()).all()
        
        return [
            {
                "amount": float(txn.amount),
                "created_at": txn.created_at,
                "merchant": txn.merchant
            }
            for txn in transactions
        ]
    
    async def _detect_amount_escalation(self, user_id: int, transactions: List[Dict[str, Any]]) -> Optional[PatternMatch]:
        """Detect escalating transaction amounts"""
        if len(transactions) < 5:
            return None
            
        amounts = [txn["amount"] for txn in transactions]
        
        # Look for escalation pattern in recent transactions
        escalation_detected = False
        escalation_evidence = []
        
        for i in range(1, len(amounts)):
            if amounts[i] >= amounts[i-1] * self.escalation_factor:
                escalation_detected = True
                escalation_evidence.append({
                    "from_amount": amounts[i-1],
                    "to_amount": amounts[i],
                    "factor": amounts[i] / amounts[i-1],
                    "timestamp": transactions[i]["created_at"].isoformat()
                })
        
        if escalation_detected and len(escalation_evidence) >= 2:
            confidence = min(len(escalation_evidence) * 0.3, 1.0)
            risk_score = self._calculate_risk_score(PatternType.AMOUNT_ESCALATION, confidence)
            
            return PatternMatch(
                pattern_type=PatternType.AMOUNT_ESCALATION,
                confidence=confidence,
                risk_score=risk_score,
                evidence={
                    "escalations": escalation_evidence,
                    "total_escalations": len(escalation_evidence),
                    "max_factor": max(e["factor"] for e in escalation_evidence)
                },
                affected_entities=[str(user_id)],
                time_window=(transactions[0]["created_at"], transactions[-1]["created_at"]),
                metadata={"detector": "amount", "user_id": user_id}
            )
        
        return None
    
    async def _detect_round_numbers(self, user_id: int, transactions: List[Dict[str, Any]]) -> Optional[PatternMatch]:
        """Detect suspicious round number patterns"""
        if len(transactions) < 10:
            return None
            
        amounts = [txn["amount"] for txn in transactions]
        
        # Check for round numbers (ending in 00, 000, etc.)
        round_numbers = []
        for amount in amounts:
            if amount % 100 == 0 or amount % 1000 == 0:
                round_numbers.append(amount)
        
        round_number_ratio = len(round_numbers) / len(amounts)
        
        if round_number_ratio >= self.round_number_threshold:
            confidence = round_number_ratio
            risk_score = self._calculate_risk_score(PatternType.AMOUNT_ROUND_NUMBERS, confidence)
            
            return PatternMatch(
                pattern_type=PatternType.AMOUNT_ROUND_NUMBERS,
                confidence=confidence,
                risk_score=risk_score,
                evidence={
                    "round_numbers": round_numbers,
                    "total_transactions": len(amounts),
                    "round_number_ratio": round_number_ratio,
                    "threshold": self.round_number_threshold
                },
                affected_entities=[str(user_id)],
                time_window=(transactions[0]["created_at"], transactions[-1]["created_at"]),
                metadata={"detector": "amount", "user_id": user_id}
            )
        
        return None

class LocationPatternDetector(BasePatternDetector):
    """Detects location-based fraud patterns"""
    
    def __init__(self, redis_client: Redis):
        super().__init__(redis_client)
        self.impossible_speed_kmh = 1000  # km/h - faster than commercial flight
        self.high_risk_countries = {
            "XX", "YY", "ZZ"  # Placeholder country codes
        }
        self.rapid_change_threshold = 3  # locations in 1 hour
        
    async def detect(self, user_id: int, transaction_data: Dict[str, Any]) -> List[PatternMatch]:
        """Detect location-based patterns"""
        patterns = []
        
        # Get location history
        location_history = await self._get_location_history(user_id)
        
        # Check for impossible travel
        impossible_travel = await self._detect_impossible_travel(user_id, location_history)
        if impossible_travel:
            patterns.append(impossible_travel)
            
        # Check for high-risk country transactions
        high_risk_pattern = await self._detect_high_risk_country(user_id, transaction_data)
        if high_risk_pattern:
            patterns.append(high_risk_pattern)
            
        # Check for rapid location changes
        rapid_changes = await self._detect_rapid_location_changes(user_id, location_history)
        if rapid_changes:
            patterns.append(rapid_changes)
            
        return patterns
    
    async def _get_location_history(self, user_id: int, hours: int = 24) -> List[Dict[str, Any]]:
        """Get recent location history for user"""
        db = next(get_db())
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        transactions = db.query(Transaction).filter(
            Transaction.user_id == user_id,
            Transaction.created_at >= cutoff_time,
            Transaction.latitude.isnot(None),
            Transaction.longitude.isnot(None)
        ).order_by(Transaction.created_at.asc()).all()
        
        return [
            {
                "latitude": float(txn.latitude),
                "longitude": float(txn.longitude),
                "country": txn.country,
                "city": txn.city,
                "created_at": txn.created_at,
                "transaction_id": txn.id
            }
            for txn in transactions
        ]
    
    async def _detect_impossible_travel(self, user_id: int, locations: List[Dict[str, Any]]) -> Optional[PatternMatch]:
        """Detect impossible travel between locations"""
        if len(locations) < 2:
            return None
            
        impossible_travels = []
        
        for i in range(1, len(locations)):
            prev_location = locations[i-1]
            curr_location = locations[i]
            
            # Calculate distance and time
            distance_km = geodesic(
                (prev_location["latitude"], prev_location["longitude"]),
                (curr_location["latitude"], curr_location["longitude"])
            ).kilometers
            
            time_diff = (curr_location["created_at"] - prev_location["created_at"]).total_seconds() / 3600  # hours
            
            if time_diff > 0:
                speed_kmh = distance_km / time_diff
                
                if speed_kmh > self.impossible_speed_kmh:
                    impossible_travels.append({
                        "from_location": {
                            "lat": prev_location["latitude"],
                            "lng": prev_location["longitude"],
                            "country": prev_location["country"],
                            "timestamp": prev_location["created_at"].isoformat()
                        },
                        "to_location": {
                            "lat": curr_location["latitude"],
                            "lng": curr_location["longitude"],
                            "country": curr_location["country"],
                            "timestamp": curr_location["created_at"].isoformat()
                        },
                        "distance_km": distance_km,
                        "time_hours": time_diff,
                        "speed_kmh": speed_kmh
                    })
        
        if impossible_travels:
            confidence = min(len(impossible_travels) * 0.5, 1.0)
            risk_score = self._calculate_risk_score(PatternType.LOCATION_IMPOSSIBLE_TRAVEL, confidence)
            
            return PatternMatch(
                pattern_type=PatternType.LOCATION_IMPOSSIBLE_TRAVEL,
                confidence=confidence,
                risk_score=risk_score,
                evidence={
                    "impossible_travels": impossible_travels,
                    "count": len(impossible_travels),
                    "max_speed": max(t["speed_kmh"] for t in impossible_travels)
                },
                affected_entities=[str(user_id)],
                time_window=(locations[0]["created_at"], locations[-1]["created_at"]),
                metadata={"detector": "location", "user_id": user_id}
            )
        
        return None
    
    async def _detect_high_risk_country(self, user_id: int, transaction_data: Dict[str, Any]) -> Optional[PatternMatch]:
        """Detect transactions from high-risk countries"""
        country = transaction_data.get("country")
        
        if country in self.high_risk_countries:
            # Check user's typical countries
            typical_countries = await self._get_user_typical_countries(user_id)
            
            if country not in typical_countries:
                confidence = 0.8
                risk_score = self._calculate_risk_score(PatternType.LOCATION_HIGH_RISK_COUNTRY, confidence)
                
                return PatternMatch(
                    pattern_type=PatternType.LOCATION_HIGH_RISK_COUNTRY,
                    confidence=confidence,
                    risk_score=risk_score,
                    evidence={
                        "country": country,
                        "typical_countries": typical_countries,
                        "is_new_country": True
                    },
                    affected_entities=[str(user_id)],
                    time_window=(datetime.utcnow(), datetime.utcnow()),
                    metadata={"detector": "location", "user_id": user_id}
                )
        
        return None
    
    async def _detect_rapid_location_changes(self, user_id: int, locations: List[Dict[str, Any]]) -> Optional[PatternMatch]:
        """Detect rapid changes in location"""
        if len(locations) < self.rapid_change_threshold:
            return None
            
        # Group locations by hour
        hourly_locations = defaultdict(set)
        
        for location in locations:
            hour_key = location["created_at"].replace(minute=0, second=0, microsecond=0)
            country = location["country"]
            if country:
                hourly_locations[hour_key].add(country)
        
        # Find hours with multiple countries
        rapid_changes = []
        for hour, countries in hourly_locations.items():
            if len(countries) >= self.rapid_change_threshold:
                rapid_changes.append({
                    "hour": hour.isoformat(),
                    "countries": list(countries),
                    "count": len(countries)
                })
        
        if rapid_changes:
            confidence = min(len(rapid_changes) * 0.4, 1.0)
            risk_score = self._calculate_risk_score(PatternType.LOCATION_RAPID_CHANGES, confidence)
            
            return PatternMatch(
                pattern_type=PatternType.LOCATION_RAPID_CHANGES,
                confidence=confidence,
                risk_score=risk_score,
                evidence={
                    "rapid_changes": rapid_changes,
                    "total_hours_affected": len(rapid_changes),
                    "max_countries_per_hour": max(rc["count"] for rc in rapid_changes)
                },
                affected_entities=[str(user_id)],
                time_window=(locations[0]["created_at"], locations[-1]["created_at"]),
                metadata={"detector": "location", "user_id": user_id}
            )
        
        return None
    
    async def _get_user_typical_countries(self, user_id: int) -> Set[str]:
        """Get user's typical transaction countries"""
        cache_key = f"user_countries:{user_id}"
        cached_countries = self.redis.get(cache_key)
        
        if cached_countries:
            return set(json.loads(cached_countries))
        
        db = next(get_db())
        cutoff_date = datetime.utcnow() - timedelta(days=90)
        
        countries = db.query(Transaction.country).filter(
            Transaction.user_id == user_id,
            Transaction.created_at >= cutoff_date,
            Transaction.country.isnot(None)
        ).distinct().all()
        
        country_set = {country[0] for country in countries if country[0]}
        
        # Cache for 1 hour
        self.redis.setex(cache_key, 3600, json.dumps(list(country_set)))
        
        return country_set

class DevicePatternDetector(BasePatternDetector):
    """Detects device-based fraud patterns"""
    
    def __init__(self, redis_client: Redis):
        super().__init__(redis_client)
        self.multiple_accounts_threshold = 5
        
    async def detect(self, user_id: int, transaction_data: Dict[str, Any]) -> List[PatternMatch]:
        """Detect device-based patterns"""
        patterns = []
        
        device_fingerprint = transaction_data.get("device_fingerprint")
        if not device_fingerprint:
            return patterns
        
        # Check for multiple accounts on same device
        multiple_accounts = await self._detect_multiple_accounts(device_fingerprint)
        if multiple_accounts:
            patterns.append(multiple_accounts)
            
        # Check for suspicious device fingerprint
        suspicious_device = await self._detect_suspicious_fingerprint(device_fingerprint)
        if suspicious_device:
            patterns.append(suspicious_device)
            
        return patterns
    
    async def _detect_multiple_accounts(self, device_fingerprint: str) -> Optional[PatternMatch]:
        """Detect multiple accounts using same device"""
        cache_key = f"device_users:{hashlib.md5(device_fingerprint.encode()).hexdigest()}"
        
        # Get users associated with this device
        db = next(get_db())
        cutoff_date = datetime.utcnow() - timedelta(days=30)
        
        user_ids = db.query(Transaction.user_id).filter(
            Transaction.device_fingerprint == device_fingerprint,
            Transaction.created_at >= cutoff_date
        ).distinct().all()
        
        unique_users = {user_id[0] for user_id in user_ids}
        
        if len(unique_users) >= self.multiple_accounts_threshold:
            confidence = min(len(unique_users) / 10.0, 1.0)
            risk_score = self._calculate_risk_score(PatternType.DEVICE_MULTIPLE_ACCOUNTS, confidence)
            
            return PatternMatch(
                pattern_type=PatternType.DEVICE_MULTIPLE_ACCOUNTS,
                confidence=confidence,
                risk_score=risk_score,
                evidence={
                    "device_fingerprint_hash": hashlib.md5(device_fingerprint.encode()).hexdigest(),
                    "user_count": len(unique_users),
                    "threshold": self.multiple_accounts_threshold,
                    "user_ids": list(unique_users)[:10]  # Limit for privacy
                },
                affected_entities=list(map(str, unique_users)),
                time_window=(cutoff_date, datetime.utcnow()),
                metadata={"detector": "device"}
            )
        
        return None
    
    async def _detect_suspicious_fingerprint(self, device_fingerprint: str) -> Optional[PatternMatch]:
        """Detect suspicious device fingerprints"""
        # Parse device fingerprint for suspicious characteristics
        try:
            fingerprint_data = json.loads(device_fingerprint)
        except:
            return None
        
        suspicious_indicators = []
        
        # Check for automation indicators
        user_agent = fingerprint_data.get("user_agent", "")
        if user_agent:
            ua = user_agents.parse(user_agent)
            if "bot" in user_agent.lower() or "crawler" in user_agent.lower():
                suspicious_indicators.append("bot_user_agent")
        
        # Check for missing common properties
        expected_properties = ["screen_resolution", "timezone", "language", "plugins"]
        missing_properties = [prop for prop in expected_properties if prop not in fingerprint_data]
        
        if len(missing_properties) > 2:
            suspicious_indicators.append("missing_properties")
        
        # Check for unusual values
        screen_res = fingerprint_data.get("screen_resolution", "")
        if screen_res in ["1x1", "0x0"]:
            suspicious_indicators.append("unusual_screen_resolution")
        
        if len(suspicious_indicators) >= 2:
            confidence = min(len(suspicious_indicators) * 0.3, 1.0)
            risk_score = self._calculate_risk_score(PatternType.DEVICE_SUSPICIOUS_FINGERPRINT, confidence)
            
            return PatternMatch(
                pattern_type=PatternType.DEVICE_SUSPICIOUS_FINGERPRINT,
                confidence=confidence,
                risk_score=risk_score,
                evidence={
                    "suspicious_indicators": suspicious_indicators,
                    "fingerprint_hash": hashlib.md5(device_fingerprint.encode()).hexdigest(),
                    "missing_properties": missing_properties
                },
                affected_entities=[],
                time_window=(datetime.utcnow(), datetime.utcnow()),
                metadata={"detector": "device"}
            )
        
        return None

class BehavioralPatternDetector(BasePatternDetector):
    """Detects behavioral fraud patterns"""
    
    def __init__(self, redis_client: Redis):
        super().__init__(redis_client)
        
    async def detect(self, user_id: int, transaction_data: Dict[str, Any]) -> List[PatternMatch]:
        """Detect behavioral patterns"""
        patterns = []
        
        # Get user's behavioral profile
        behavioral_profile = await self._get_behavioral_profile(user_id)
        
        # Check for time anomalies
        time_anomaly = await self._detect_time_anomaly(user_id, transaction_data, behavioral_profile)
        if time_anomaly:
            patterns.append(time_anomaly)
            
        # Check for merchant anomalies
        merchant_anomaly = await self._detect_merchant_anomaly(user_id, transaction_data, behavioral_profile)
        if merchant_anomaly:
            patterns.append(merchant_anomaly)
            
        return patterns
    
    async def _get_behavioral_profile(self, user_id: int) -> Dict[str, Any]:
        """Get user's behavioral profile"""
        cache_key = f"behavioral_profile:{user_id}"
        cached_profile = self.redis.get(cache_key)
        
        if cached_profile:
            return json.loads(cached_profile)
        
        db = next(get_db())
        cutoff_date = datetime.utcnow() - timedelta(days=90)
        
        transactions = db.query(Transaction).filter(
            Transaction.user_id == user_id,
            Transaction.created_at >= cutoff_date,
            Transaction.status == "completed"
        ).all()
        
        if not transactions:
            return {}
        
        # Analyze transaction times
        hours = [txn.created_at.hour for txn in transactions]
        days = [txn.created_at.weekday() for txn in transactions]
        
        # Analyze merchants
        merchants = [txn.merchant for txn in transactions if txn.merchant]
        merchant_counts = defaultdict(int)
        for merchant in merchants:
            merchant_counts[merchant] += 1
        
        profile = {
            "typical_hours": list(set(hours)),
            "typical_days": list(set(days)),
            "common_merchants": dict(merchant_counts),
            "avg_amount": np.mean([float(txn.amount) for txn in transactions]),
            "transaction_count": len(transactions)
        }
        
        # Cache for 6 hours
        self.redis.setex(cache_key, 21600, json.dumps(profile, default=str))
        
        return profile
    
    async def _detect_time_anomaly(self, user_id: int, transaction_data: Dict[str, Any], profile: Dict[str, Any]) -> Optional[PatternMatch]:
        """Detect unusual transaction times"""
        if not profile or "typical_hours" not in profile:
            return None
        
        current_hour = datetime.utcnow().hour
        typical_hours = profile["typical_hours"]
        
        # Check if current hour is unusual for this user
        if current_hour not in typical_hours and len(typical_hours) > 5:
            # Calculate how unusual this time is
            hour_distances = [min(abs(current_hour - h), 24 - abs(current_hour - h)) for h in typical_hours]
            min_distance = min(hour_distances)
            
            if min_distance >= 4:  # At least 4 hours from typical times
                confidence = min(min_distance / 12.0, 1.0)  # Max at 12 hours difference
                risk_score = self._calculate_risk_score(PatternType.BEHAVIORAL_TIME_ANOMALY, confidence)
                
                return PatternMatch(
                    pattern_type=PatternType.BEHAVIORAL_TIME_ANOMALY,
                    confidence=confidence,
                    risk_score=risk_score,
                    evidence={
                        "current_hour": current_hour,
                        "typical_hours": typical_hours,
                        "min_distance_hours": min_distance,
                        "transaction_count": profile.get("transaction_count", 0)
                    },
                    affected_entities=[str(user_id)],
                    time_window=(datetime.utcnow(), datetime.utcnow()),
                    metadata={"detector": "behavioral", "user_id": user_id}
                )
        
        return None
    
    async def _detect_merchant_anomaly(self, user_id: int, transaction_data: Dict[str, Any], profile: Dict[str, Any]) -> Optional[PatternMatch]:
        """Detect unusual merchant patterns"""
        if not profile or "common_merchants" not in profile:
            return None
        
        current_merchant = transaction_data.get("merchant")
        if not current_merchant:
            return None
        
        common_merchants = profile["common_merchants"]
        
        # Check if this is a completely new merchant
        if current_merchant not in common_merchants and len(common_merchants) > 10:
            confidence = 0.6  # Moderate confidence for new merchant
            risk_score = self._calculate_risk_score(PatternType.BEHAVIORAL_MERCHANT_ANOMALY, confidence)
            
            return PatternMatch(
                pattern_type=PatternType.BEHAVIORAL_MERCHANT_ANOMALY,
                confidence=confidence,
                risk_score=risk_score,
                evidence={
                    "current_merchant": current_merchant,
                    "is_new_merchant": True,
                    "known_merchant_count": len(common_merchants),
                    "top_merchants": dict(sorted(common_merchants.items(), key=lambda x: x[1], reverse=True)[:5])
                },
                affected_entities=[str(user_id)],
                time_window=(datetime.utcnow(), datetime.utcnow()),
                metadata={"detector": "behavioral", "user_id": user_id}
            )
        
        return None

class NetworkPatternDetector(BasePatternDetector):
    """Detects network-based fraud patterns"""
    
    def __init__(self, redis_client: Redis):
        super().__init__(redis_client)
        self.coordinated_threshold = 5  # users
        self.time_window = 300  # 5 minutes
        
    async def detect(self, ip_address: str, transaction_data: Dict[str, Any]) -> List[PatternMatch]:
        """Detect network-based patterns"""
        patterns = []
        
        # Check for coordinated attacks
        coordinated_attack = await self._detect_coordinated_attack(ip_address)
        if coordinated_attack:
            patterns.append(coordinated_attack)
            
        # Check for account enumeration
        enumeration_attack = await self._detect_account_enumeration(ip_address)
        if enumeration_attack:
            patterns.append(enumeration_attack)
            
        return patterns
    
    async def _detect_coordinated_attack(self, ip_address: str) -> Optional[PatternMatch]:
        """Detect coordinated attacks from same IP"""
        cache_key = f"ip_activity:{hashlib.md5(ip_address.encode()).hexdigest()}"
        
        # Track recent activity from this IP
        now = datetime.utcnow()
        cutoff_time = now - timedelta(seconds=self.time_window)
        
        # Get recent transactions from this IP
        db = next(get_db())
        recent_transactions = db.query(Transaction).filter(
            Transaction.ip_address == ip_address,
            Transaction.created_at >= cutoff_time
        ).all()
        
        # Count unique users
        unique_users = set(txn.user_id for txn in recent_transactions)
        
        if len(unique_users) >= self.coordinated_threshold:
            confidence = min(len(unique_users) / 10.0, 1.0)
            risk_score = self._calculate_risk_score(PatternType.NETWORK_COORDINATED_ATTACK, confidence)
            
            return PatternMatch(
                pattern_type=PatternType.NETWORK_COORDINATED_ATTACK,
                confidence=confidence,
                risk_score=risk_score,
                evidence={
                    "ip_address_hash": hashlib.md5(ip_address.encode()).hexdigest(),
                    "unique_users": len(unique_users),
                    "total_transactions": len(recent_transactions),
                    "time_window_seconds": self.time_window,
                    "threshold": self.coordinated_threshold
                },
                affected_entities=list(map(str, unique_users)),
                time_window=(cutoff_time, now),
                metadata={"detector": "network", "ip_hash": hashlib.md5(ip_address.encode()).hexdigest()}
            )
        
        return None
    
    async def _detect_account_enumeration(self, ip_address: str) -> Optional[PatternMatch]:
        """Detect account enumeration attempts"""
        # This would typically look at failed login attempts, but we'll check failed transactions
        db = next(get_db())
        cutoff_time = datetime.utcnow() - timedelta(minutes=15)
        
        failed_transactions = db.query(Transaction).filter(
            Transaction.ip_address == ip_address,
            Transaction.created_at >= cutoff_time,
            Transaction.status == "failed"
        ).all()
        
        if len(failed_transactions) >= 10:  # Many failed attempts
            unique_users = set(txn.user_id for txn in failed_transactions)
            
            if len(unique_users) >= 5:  # Targeting multiple users
                confidence = min(len(unique_users) / 20.0, 1.0)
                risk_score = self._calculate_risk_score(PatternType.NETWORK_ACCOUNT_ENUMERATION, confidence)
                
                return PatternMatch(
                    pattern_type=PatternType.NETWORK_ACCOUNT_ENUMERATION,
                    confidence=confidence,
                    risk_score=risk_score,
                    evidence={
                        "ip_address_hash": hashlib.md5(ip_address.encode()).hexdigest(),
                        "failed_attempts": len(failed_transactions),
                        "targeted_users": len(unique_users),
                        "time_window_minutes": 15
                    },
                    affected_entities=list(map(str, unique_users)),
                    time_window=(cutoff_time, datetime.utcnow()),
                    metadata={"detector": "network", "ip_hash": hashlib.md5(ip_address.encode()).hexdigest()}
                )
        
        return None

class PaymentPatternDetector(BasePatternDetector):
    """Detects payment method fraud patterns"""
    
    def __init__(self, redis_client: Redis):
        super().__init__(redis_client)
        self.testing_threshold = 10  # attempts
        self.testing_window = 3600    # 1 hour
        
    async def detect(self, user_id: int, transaction_data: Dict[str, Any]) -> List[PatternMatch]:
        """Detect payment method patterns"""
        patterns = []
        
        # Check for payment method testing
        testing_pattern = await self._detect_payment_testing(user_id)
        if testing_pattern:
            patterns.append(testing_pattern)
            
        return patterns
    
    async def _detect_payment_testing(self, user_id: int) -> Optional[PatternMatch]:
        """Detect payment method testing (card testing)"""
        db = next(get_db())
        cutoff_time = datetime.utcnow() - timedelta(seconds=self.testing_window)
        
        # Get recent transactions with different payment methods
        recent_transactions = db.query(Transaction).filter(
            Transaction.user_id == user_id,
            Transaction.created_at >= cutoff_time
        ).all()
        
        # Count unique payment methods and failed attempts
        payment_methods = set()
        failed_count = 0
        
        for txn in recent_transactions:
            if txn.payment_method:
                payment_methods.add(txn.payment_method)
            if txn.status == "failed":
                failed_count += 1
        
        # Pattern: Many different payment methods with high failure rate
        if len(payment_methods) >= 5 and failed_count >= self.testing_threshold:
            failure_rate = failed_count / len(recent_transactions)
            
            if failure_rate >= 0.7:  # 70% failure rate
                confidence = min(len(payment_methods) / 10.0, 1.0)
                risk_score = self._calculate_risk_score(PatternType.PAYMENT_METHOD_TESTING, confidence)
                
                return PatternMatch(
                    pattern_type=PatternType.PAYMENT_METHOD_TESTING,
                    confidence=confidence,
                    risk_score=risk_score,
                    evidence={
                        "unique_payment_methods": len(payment_methods),
                        "failed_attempts": failed_count,
                        "total_attempts": len(recent_transactions),
                        "failure_rate": failure_rate,
                        "time_window_seconds": self.testing_window
                    },
                    affected_entities=[str(user_id)],
                    time_window=(cutoff_time, datetime.utcnow()),
                    metadata={"detector": "payment", "user_id": user_id}
                )
        
        return None

class PatternDetectionEngine:
    """Main pattern detection engine that coordinates all detectors"""
    
    def __init__(self, redis_client: Redis):
        self.redis = redis_client
        
        # Initialize all pattern detectors
        self.detectors = {
            "velocity": VelocityPatternDetector(redis_client),
            "amount": AmountPatternDetector(redis_client),
            "location": LocationPatternDetector(redis_client),
            "device": DevicePatternDetector(redis_client),
            "behavioral": BehavioralPatternDetector(redis_client),
            "network": NetworkPatternDetector(redis_client),
            "payment": PaymentPatternDetector(redis_client)
        }
        
    async def detect_all_patterns(self, user_id: int, transaction_data: Dict[str, Any]) -> List[PatternMatch]:
        """Run all pattern detectors and return combined results"""
        all_patterns = []
        
        # Run detectors in parallel
        detection_tasks = []
        
        # User-specific detectors
        detection_tasks.extend([
            self.detectors["velocity"].detect(user_id, transaction_data),
            self.detectors["amount"].detect(user_id, transaction_data),
            self.detectors["location"].detect(user_id, transaction_data),
            self.detectors["device"].detect(user_id, transaction_data),
            self.detectors["behavioral"].detect(user_id, transaction_data),
            self.detectors["payment"].detect(user_id, transaction_data)
        ])
        
        # Network-specific detectors
        if "ip_address" in transaction_data:
            detection_tasks.append(
                self.detectors["network"].detect(transaction_data["ip_address"], transaction_data)
            )
        
        # Execute all detectors
        try:
            results = await asyncio.gather(*detection_tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, list):
                    all_patterns.extend(result)
                elif isinstance(result, Exception):
                    logger.error(f"Pattern detection failed: {result}")
            
        except Exception as e:
            logger.error(f"Pattern detection engine failed: {e}")
        
        # Sort patterns by risk score (highest first)
        all_patterns.sort(key=lambda p: p.risk_score, reverse=True)
        
        return all_patterns
    
    async def get_pattern_statistics(self, days: int = 7) -> Dict[str, Any]:
        """Get pattern detection statistics"""
        try:
            db = next(get_db())
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # This would query a patterns table if we had one
            # For now, return mock statistics
            
            return {
                "timeframe_days": days,
                "total_patterns_detected": 156,
                "pattern_types": {
                    "velocity_burst": 45,
                    "location_impossible_travel": 23,
                    "device_multiple_accounts": 18,
                    "amount_escalation": 15,
                    "behavioral_time_anomaly": 12,
                    "network_coordinated_attack": 8,
                    "payment_method_testing": 6,
                    "other": 29
                },
                "high_risk_patterns": 34,
                "patterns_per_day": 156 / days
            }
            
        except Exception as e:
            logger.error(f"Failed to get pattern statistics: {e}")
            return {}