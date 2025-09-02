import re
import hashlib
import json
import base64
import qrcode
import cv2
import numpy as np
from PIL import Image
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
import logging
from urllib.parse import urlparse, parse_qs
import requests
from io import BytesIO
import magic
import phonenumbers
from email.utils import parseaddr
import tldextract

from ..config import settings

logger = logging.getLogger(__name__)

class ContentAnalyzer:
    """Analyze content for potential threats"""
    
    # Suspicious keywords for different threat types
    PHISHING_KEYWORDS = [
        'urgent', 'verify', 'suspend', 'click here', 'act now', 'limited time',
        'congratulations', 'winner', 'prize', 'lottery', 'claim now',
        'bank account', 'credit card', 'social security', 'password',
        'otp', 'pin', 'cvv', 'expire', 'update payment'
    ]
    
    SCAM_KEYWORDS = [
        'free money', 'easy money', 'work from home', 'guaranteed income',
        'investment opportunity', 'double your money', 'risk free',
        'get rich quick', 'make money fast', 'no experience required'
    ]
    
    MALWARE_EXTENSIONS = [
        '.exe', '.scr', '.bat', '.com', '.pif', '.vbs', '.js',
        '.jar', '.apk', '.dmg', '.pkg', '.deb', '.rpm'
    ]
    
    SUSPICIOUS_DOMAINS = [
        'bit.ly', 'tinyurl.com', 'short.link', 'cutt.ly',
        'rebrand.ly', 't.co', 'ow.ly', 'buff.ly'
    ]

    @staticmethod
    def analyze_text(text: str) -> Dict[str, Any]:
        """Analyze text content for threats"""
        if not text:
            return {"threat_score": 0, "threats": []}
        
        text_lower = text.lower()
        threats = []
        threat_score = 0
        
        # Check for phishing keywords
        phishing_matches = [kw for kw in ContentAnalyzer.PHISHING_KEYWORDS if kw in text_lower]
        if phishing_matches:
            threat_score += len(phishing_matches) * 10
            threats.append({
                "type": "phishing_keywords",
                "severity": "medium" if len(phishing_matches) < 3 else "high",
                "matches": phishing_matches
            })
        
        # Check for scam keywords
        scam_matches = [kw for kw in ContentAnalyzer.SCAM_KEYWORDS if kw in text_lower]
        if scam_matches:
            threat_score += len(scam_matches) * 15
            threats.append({
                "type": "scam_keywords",
                "severity": "high",
                "matches": scam_matches
            })
        
        # Check for URLs
        urls = ContentAnalyzer.extract_urls(text)
        if urls:
            url_analysis = ContentAnalyzer.analyze_urls(urls)
            if url_analysis["suspicious_urls"]:
                threat_score += len(url_analysis["suspicious_urls"]) * 20
                threats.append({
                    "type": "suspicious_urls",
                    "severity": "high",
                    "urls": url_analysis["suspicious_urls"]
                })
        
        # Check for phone numbers
        phone_numbers = ContentAnalyzer.extract_phone_numbers(text)
        if phone_numbers:
            phone_analysis = ContentAnalyzer.analyze_phone_numbers(phone_numbers)
            if phone_analysis["suspicious"]:
                threat_score += 15
                threats.append({
                    "type": "suspicious_phone",
                    "severity": "medium",
                    "numbers": phone_analysis["suspicious"]
                })
        
        # Check for email addresses
        emails = ContentAnalyzer.extract_emails(text)
        if emails:
            email_analysis = ContentAnalyzer.analyze_emails(emails)
            if email_analysis["suspicious"]:
                threat_score += 10
                threats.append({
                    "type": "suspicious_email",
                    "severity": "medium",
                    "emails": email_analysis["suspicious"]
                })
        
        return {
            "threat_score": min(threat_score, 100),
            "threats": threats,
            "analysis": {
                "urls_found": len(urls) if urls else 0,
                "phones_found": len(phone_numbers) if phone_numbers else 0,
                "emails_found": len(emails) if emails else 0
            }
        }
    
    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """Extract URLs from text"""
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        return re.findall(url_pattern, text)
    
    @staticmethod
    def analyze_urls(urls: List[str]) -> Dict[str, Any]:
        """Analyze URLs for suspicious patterns"""
        suspicious_urls = []
        
        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                
                # Check against suspicious domains
                if any(sus_domain in domain for sus_domain in ContentAnalyzer.SUSPICIOUS_DOMAINS):
                    suspicious_urls.append({
                        "url": url,
                        "reason": "suspicious_domain",
                        "domain": domain
                    })
                    continue
                
                # Check for URL shorteners
                if ContentAnalyzer.is_url_shortener(domain):
                    suspicious_urls.append({
                        "url": url,
                        "reason": "url_shortener",
                        "domain": domain
                    })
                    continue
                
                # Check for suspicious TLD
                extracted = tldextract.extract(url)
                if extracted.suffix in ['tk', 'ml', 'ga', 'cf']:
                    suspicious_urls.append({
                        "url": url,
                        "reason": "suspicious_tld",
                        "tld": extracted.suffix
                    })
                
            except Exception as e:
                logger.warning(f"Failed to analyze URL {url}: {e}")
        
        return {
            "total_urls": len(urls),
            "suspicious_urls": suspicious_urls,
            "clean_urls": len(urls) - len(suspicious_urls)
        }
    
    @staticmethod
    def is_url_shortener(domain: str) -> bool:
        """Check if domain is a URL shortener"""
        shorteners = [
            'bit.ly', 'tinyurl.com', 'short.link', 'cutt.ly', 'rebrand.ly',
            't.co', 'ow.ly', 'buff.ly', 'is.gd', 'v.gd', 'x.co'
        ]
        return domain in shorteners
    
    @staticmethod
    def extract_phone_numbers(text: str) -> List[str]:
        """Extract phone numbers from text"""
        # Indian phone number patterns
        patterns = [
            r'\+91[6-9]\d{9}',
            r'91[6-9]\d{9}',
            r'[6-9]\d{9}'
        ]
        
        phone_numbers = []
        for pattern in patterns:
            matches = re.findall(pattern, text)
            phone_numbers.extend(matches)
        
        return list(set(phone_numbers))  # Remove duplicates
    
    @staticmethod
    def analyze_phone_numbers(phone_numbers: List[str]) -> Dict[str, Any]:
        """Analyze phone numbers for suspicious patterns"""
        suspicious = []
        
        for number in phone_numbers:
            try:
                # Parse with phonenumbers library
                parsed = phonenumbers.parse(number, "IN")
                
                if not phonenumbers.is_valid_number(parsed):
                    suspicious.append({
                        "number": number,
                        "reason": "invalid_format"
                    })
                    continue
                
                # Check for known scam number patterns
                if ContentAnalyzer.is_suspicious_number(number):
                    suspicious.append({
                        "number": number,
                        "reason": "suspicious_pattern"
                    })
                
            except Exception as e:
                suspicious.append({
                    "number": number,
                    "reason": "parse_error"
                })
        
        return {
            "total_numbers": len(phone_numbers),
            "suspicious": suspicious,
            "clean": len(phone_numbers) - len(suspicious)
        }
    
    @staticmethod
    def is_suspicious_number(number: str) -> bool:
        """Check if phone number matches suspicious patterns"""
        # Remove country code for pattern matching
        clean_number = re.sub(r'^\+?91', '', number)
        
        # Suspicious patterns
        suspicious_patterns = [
            r'^0+',  # Starts with zeros
            r'^1+',  # Starts with ones
            r'(\d)\1{8,}',  # Repeated digits
            r'^[0-5]',  # Doesn't start with valid mobile prefix
        ]
        
        for pattern in suspicious_patterns:
            if re.match(pattern, clean_number):
                return True
        
        return False
    
    @staticmethod
    def extract_emails(text: str) -> List[str]:
        """Extract email addresses from text"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return re.findall(email_pattern, text)
    
    @staticmethod
    def analyze_emails(emails: List[str]) -> Dict[str, Any]:
        """Analyze email addresses for suspicious patterns"""
        suspicious = []
        
        for email in emails:
            try:
                name, addr = parseaddr(email)
                domain = addr.split('@')[1].lower()
                
                # Check for suspicious domains
                if ContentAnalyzer.is_suspicious_email_domain(domain):
                    suspicious.append({
                        "email": email,
                        "reason": "suspicious_domain",
                        "domain": domain
                    })
                    continue
                
                # Check for typosquatting
                if ContentAnalyzer.is_typosquatting_domain(domain):
                    suspicious.append({
                        "email": email,
                        "reason": "typosquatting",
                        "domain": domain
                    })
                
            except Exception as e:
                suspicious.append({
                    "email": email,
                    "reason": "parse_error"
                })
        
        return {
            "total_emails": len(emails),
            "suspicious": suspicious,
            "clean": len(emails) - len(suspicious)
        }
    
    @staticmethod
    def is_suspicious_email_domain(domain: str) -> bool:
        """Check if email domain is suspicious"""
        suspicious_domains = [
            'tempmail.org', '10minutemail.com', 'guerrillamail.com',
            'mailinator.com', 'yopmail.com', 'temp-mail.org'
        ]
        return domain in suspicious_domains
    
    @staticmethod
    def is_typosquatting_domain(domain: str) -> bool:
        """Check for typosquatting of popular domains"""
        legitimate_domains = [
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
            'paypal.com', 'amazon.com', 'google.com', 'facebook.com'
        ]
        
        for legit_domain in legitimate_domains:
            # Simple Levenshtein distance check
            if ContentAnalyzer.levenshtein_distance(domain, legit_domain) <= 2 and domain != legit_domain:
                return True
        
        return False
    
    @staticmethod
    def levenshtein_distance(s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return ContentAnalyzer.levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]

class QRCodeAnalyzer:
    """Analyze QR codes for malicious content"""
    
    @staticmethod
    def extract_qr_codes(image_path: str) -> List[Dict[str, Any]]:
        """Extract QR codes from image"""
        try:
            # Read image
            image = cv2.imread(image_path)
            if image is None:
                return []
            
            # Initialize QR code detector
            detector = cv2.QRCodeDetector()
            
            # Detect and decode QR codes
            data, vertices_array, _ = detector.detectAndDecodeMulti(image)
            
            qr_codes = []
            if vertices_array is not None:
                for i, qr_data in enumerate(data):
                    if qr_data:
                        qr_codes.append({
                            "data": qr_data,
                            "position": vertices_array[i].tolist() if len(vertices_array) > i else None
                        })
            
            return qr_codes
            
        except Exception as e:
            logger.error(f"Failed to extract QR codes from {image_path}: {e}")
            return []
    
    @staticmethod
    def analyze_qr_content(qr_data: str) -> Dict[str, Any]:
        """Analyze QR code content for threats"""
        analysis = {
            "threat_score": 0,
            "threats": [],
            "content_type": "unknown"
        }
        
        try:
            # Determine content type
            if qr_data.startswith(('http://', 'https://')):
                analysis["content_type"] = "url"
                url_analysis = ContentAnalyzer.analyze_urls([qr_data])
                if url_analysis["suspicious_urls"]:
                    analysis["threat_score"] = 80
                    analysis["threats"].append({
                        "type": "malicious_url",
                        "severity": "high",
                        "details": url_analysis["suspicious_urls"][0]
                    })
            
            elif qr_data.startswith('tel:'):
                analysis["content_type"] = "phone"
                phone = qr_data.replace('tel:', '')
                phone_analysis = ContentAnalyzer.analyze_phone_numbers([phone])
                if phone_analysis["suspicious"]:
                    analysis["threat_score"] = 60
                    analysis["threats"].append({
                        "type": "suspicious_phone",
                        "severity": "medium",
                        "details": phone_analysis["suspicious"][0]
                    })
            
            elif qr_data.startswith('mailto:'):
                analysis["content_type"] = "email"
                email = qr_data.replace('mailto:', '')
                email_analysis = ContentAnalyzer.analyze_emails([email])
                if email_analysis["suspicious"]:
                    analysis["threat_score"] = 50
                    analysis["threats"].append({
                        "type": "suspicious_email",
                        "severity": "medium",
                        "details": email_analysis["suspicious"][0]
                    })
            
            elif qr_data.startswith('wifi:'):
                analysis["content_type"] = "wifi"
                # WiFi QR codes can be used for evil twin attacks
                analysis["threat_score"] = 30
                analysis["threats"].append({
                    "type": "wifi_config",
                    "severity": "low",
                    "message": "WiFi configuration QR code detected"
                })
            
            else:
                # Analyze as text
                text_analysis = ContentAnalyzer.analyze_text(qr_data)
                analysis["content_type"] = "text"
                analysis["threat_score"] = text_analysis["threat_score"]
                analysis["threats"] = text_analysis["threats"]
            
        except Exception as e:
            logger.error(f"Failed to analyze QR content: {e}")
            analysis["threats"].append({
                "type": "analysis_error",
                "severity": "low",
                "message": "Failed to analyze QR code content"
            })
        
        return analysis

class FileAnalyzer:
    """Analyze files for malicious content"""
    
    @staticmethod
    def analyze_file(file_path: str) -> Dict[str, Any]:
        """Analyze file for threats"""
        try:
            # Get file info
            file_info = FileAnalyzer.get_file_info(file_path)
            
            analysis = {
                "file_info": file_info,
                "threat_score": 0,
                "threats": []
            }
            
            # Check file extension
            if FileAnalyzer.is_suspicious_extension(file_info["extension"]):
                analysis["threat_score"] += 70
                analysis["threats"].append({
                    "type": "suspicious_extension",
                    "severity": "high",
                    "extension": file_info["extension"]
                })
            
            # Check MIME type mismatch
            if FileAnalyzer.has_mime_mismatch(file_path, file_info["extension"]):
                analysis["threat_score"] += 50
                analysis["threats"].append({
                    "type": "mime_mismatch",
                    "severity": "high",
                    "message": "File extension doesn't match content type"
                })
            
            # Check file size (unusually large files can be suspicious)
            if file_info["size"] > 100 * 1024 * 1024:  # 100MB
                analysis["threat_score"] += 20
                analysis["threats"].append({
                    "type": "large_file",
                    "severity": "low",
                    "size": file_info["size"]
                })
            
            return analysis
            
        except Exception as e:
            logger.error(f"Failed to analyze file {file_path}: {e}")
            return {
                "threat_score": 0,
                "threats": [{
                    "type": "analysis_error",
                    "severity": "low",
                    "message": str(e)
                }]
            }
    
    @staticmethod
    def get_file_info(file_path: str) -> Dict[str, Any]:
        """Get basic file information"""
        import os
        
        stat = os.stat(file_path)
        _, extension = os.path.splitext(file_path)
        
        return {
            "name": os.path.basename(file_path),
            "extension": extension.lower(),
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime),
            "mime_type": magic.from_file(file_path, mime=True) if magic else None
        }
    
    @staticmethod
    def is_suspicious_extension(extension: str) -> bool:
        """Check if file extension is suspicious"""
        return extension in ContentAnalyzer.MALWARE_EXTENSIONS
    
    @staticmethod
    def has_mime_mismatch(file_path: str, extension: str) -> bool:
        """Check for MIME type and extension mismatch"""
        if not magic:
            return False
        
        try:
            mime_type = magic.from_file(file_path, mime=True)
            
            # Common extension to MIME type mappings
            expected_mimes = {
                '.jpg': 'image/jpeg',
                '.jpeg': 'image/jpeg',
                '.png': 'image/png',
                '.gif': 'image/gif',
                '.pdf': 'application/pdf',
                '.doc': 'application/msword',
                '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                '.txt': 'text/plain'
            }
            
            expected_mime = expected_mimes.get(extension)
            if expected_mime and mime_type != expected_mime:
                return True
            
            return False
            
        except Exception:
            return False

class ThreatScorer:
    """Calculate overall threat scores"""
    
    SEVERITY_WEIGHTS = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4
    }
    
    @staticmethod
    def calculate_overall_score(analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate overall threat score from multiple analyses"""
        total_score = 0
        all_threats = []
        threat_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        
        for analysis in analyses:
            total_score += analysis.get("threat_score", 0)
            
            for threat in analysis.get("threats", []):
                all_threats.append(threat)
                severity = threat.get("severity", "low")
                threat_counts[severity] += 1
        
        # Calculate weighted score
        weighted_score = sum(
            count * ThreatScorer.SEVERITY_WEIGHTS[severity]
            for severity, count in threat_counts.items()
        )
        
        # Normalize to 0-100 scale
        final_score = min(total_score + weighted_score * 5, 100)
        
        # Determine overall risk level
        if final_score >= 80:
            risk_level = "critical"
        elif final_score >= 60:
            risk_level = "high"
        elif final_score >= 30:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            "overall_score": final_score,
            "risk_level": risk_level,
            "threat_counts": threat_counts,
            "total_threats": len(all_threats),
            "all_threats": all_threats
        }

def generate_content_hash(content: str) -> str:
    """Generate hash for content deduplication"""
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe storage"""
    # Remove dangerous characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Limit length
    if len(sanitized) > 255:
        name, ext = os.path.splitext(sanitized)
        sanitized = name[:255-len(ext)] + ext
    
    return sanitized

def format_file_size(size_bytes: int) -> str:
    """Format file size in human readable format"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.1f} {size_names[i]}"

def is_safe_url(url: str) -> bool:
    """Check if URL is safe to access"""
    try:
        parsed = urlparse(url)
        
        # Must have valid scheme
        if parsed.scheme not in ['http', 'https']:
            return False
        
        # Must have valid netloc
        if not parsed.netloc:
            return False
        
        # Check against known malicious domains (simplified)
        domain = parsed.netloc.lower()
        malicious_domains = ['malware.com', 'phishing.net']  # Example list
        
        if domain in malicious_domains:
            return False
        
        return True
        
    except Exception:
        return False

def extract_metadata(file_path: str) -> Dict[str, Any]:
    """Extract metadata from file"""
    try:
        metadata = {}
        
        # Basic file stats
        stat = os.stat(file_path)
        metadata.update({
            "size": stat.st_size,
            "created": datetime.fromtimestamp(stat.st_ctime),
            "modified": datetime.fromtimestamp(stat.st_mtime),
            "accessed": datetime.fromtimestamp(stat.st_atime)
        })
        
        # MIME type
        if magic:
            metadata["mime_type"] = magic.from_file(file_path, mime=True)
        
        # For images, extract EXIF data
        if file_path.lower().endswith(('.jpg', '.jpeg', '.tiff')):
            try:
                from PIL import Image
                from PIL.ExifTags import TAGS
                
                image = Image.open(file_path)
                exif_data = image.getexif()
                
                if exif_data:
                    exif = {}
                    for tag_id, value in exif_data.items():
                        tag = TAGS.get(tag_id, tag_id)
                        exif[tag] = value
                    metadata["exif"] = exif
                    
            except Exception as e:
                logger.debug(f"Failed to extract EXIF data: {e}")
        
        return metadata
        
    except Exception as e:
        logger.error(f"Failed to extract metadata from {file_path}: {e}")
        return {}

