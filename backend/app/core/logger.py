"""
Logging Module for Fraud Detection System

This module provides comprehensive logging functionality including structured logging,
log aggregation, security event logging, performance monitoring, and audit trails.
It supports multiple output formats, log rotation, and integration with external
logging services.
"""

import logging
import logging.handlers
import sys
import os
import json
import traceback
from typing import Dict, List, Optional, Any, Union, Callable
from datetime import datetime, timedelta
from pathlib import Path
from functools import wraps
from contextlib import contextmanager
from enum import Enum
import threading
import queue
import time
import gzip
import shutil

# Third-party imports
import structlog
from pythonjsonlogger import jsonlogger
import colorlog
from elastic_transport import Transport
from elasticsearch import Elasticsearch

# Local imports
from ..core import settings, cache_manager
from ..models.audit import AuditLog, LogLevel, LogCategory

class LogLevel(Enum):
    """Log levels with numeric values"""
    CRITICAL = 50
    ERROR = 40
    WARNING = 30
    INFO = 20
    DEBUG = 10
    TRACE = 5

class LogCategory(Enum):
    """Log categories for classification"""
    SECURITY = "security"
    FRAUD = "fraud"
    TRANSACTION = "transaction"
    API = "api"
    DATABASE = "database"
    CACHE = "cache"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    PERFORMANCE = "performance"
    AUDIT = "audit"
    SYSTEM = "system"
    USER_ACTION = "user_action"
    ERROR = "error"
    DEBUG = "debug"

class LogFormat(Enum):
    """Log output formats"""
    JSON = "json"
    STRUCTURED = "structured"
    CONSOLE = "console"
    SYSLOG = "syslog"

class SecurityEventType(Enum):
    """Security event types for logging"""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    ACCOUNT_LOCKED = "account_locked"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_ACCESS = "data_access"
    CONFIGURATION_CHANGE = "configuration_change"
    FRAUD_DETECTED = "fraud_detected"

class LoggerConfig:
    """Logger configuration class"""
    
    def __init__(self):
        self.level = getattr(logging, settings.log_level.upper(), logging.INFO)
        self.format = settings.log_format
        self.enable_console = True
        self.enable_file = True
        self.enable_elasticsearch = getattr(settings, 'enable_elasticsearch_logging', False)
        self.enable_syslog = getattr(settings, 'enable_syslog', False)
        
        # File logging settings
        self.log_dir = Path(getattr(settings, 'log_directory', 'logs'))
        self.max_file_size = getattr(settings, 'max_log_file_size', 100 * 1024 * 1024)  # 100MB
        self.backup_count = getattr(settings, 'log_backup_count', 10)
        self.compress_logs = getattr(settings, 'compress_old_logs', True)
        
        # Elasticsearch settings
        self.elasticsearch_hosts = getattr(settings, 'elasticsearch_hosts', ['localhost:9200'])
        self.elasticsearch_index = getattr(settings, 'elasticsearch_index', 'fraud-detection-logs')
        
        # Performance settings
        self.async_logging = getattr(settings, 'async_logging', True)
        self.buffer_size = getattr(settings, 'log_buffer_size', 1000)
        self.flush_interval = getattr(settings, 'log_flush_interval', 5)  # seconds

class CustomJSONFormatter(jsonlogger.JsonFormatter):
    """Custom JSON formatter with additional fields"""
    
    def add_fields(self, log_record, record, message_dict):
        super().add_fields(log_record, record, message_dict)
        
        # Add timestamp
        log_record['timestamp'] = datetime.utcnow().isoformat()
        
        # Add application info
        log_record['application'] = settings.app_name
        log_record['version'] = settings.app_version
        log_record['environment'] = settings.environment
        
        # Add thread info
        log_record['thread_id'] = threading.get_ident()
        log_record['thread_name'] = threading.current_thread().name
        
        # Add process info
        log_record['process_id'] = os.getpid()
        
        # Ensure level is string
        if 'level' not in log_record:
            log_record['level'] = record.levelname

class StructuredFormatter(logging.Formatter):
    """Structured formatter for console output"""
    
    def __init__(self):
        super().__init__()
        self.formatter = colorlog.ColoredFormatter(
            '%(log_color)s%(asctime)s [%(levelname)8s] %(name)s: %(message)s%(reset)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'red,bg_white',
            }
        )
    
    def format(self, record):
        return self.formatter.format(record)

class ElasticsearchHandler(logging.Handler):
    """Custom Elasticsearch logging handler"""
    
    def __init__(self, hosts, index_name):
        super().__init__()
        self.hosts = hosts
        self.index_name = index_name
        self.es_client = None
        self._connect()
    
    def _connect(self):
        """Connect to Elasticsearch"""
        try:
            self.es_client = Elasticsearch(
                hosts=self.hosts,
                timeout=30,
                max_retries=3,
                retry_on_timeout=True
            )
            # Test connection
            self.es_client.ping()
        except Exception as e:
            print(f"Failed to connect to Elasticsearch: {e}")
            self.es_client = None
    
    def emit(self, record):
        """Emit log record to Elasticsearch"""
        if not self.es_client:
            return
        
        try:
            # Format the record
            log_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'level': record.levelname,
                'logger': record.name,
                'message': record.getMessage(),
                'module': record.module,
                'function': record.funcName,
                'line': record.lineno,
                'application': settings.app_name,
                'environment': settings.environment
            }
            
            # Add exception info if present
            if record.exc_info:
                log_entry['exception'] = {
                    'type': record.exc_info[0].__name__,
                    'message': str(record.exc_info[1]),
                    'traceback': traceback.format_exception(*record.exc_info)
                }
            
            # Add extra fields
            if hasattr(record, '__dict__'):
                for key, value in record.__dict__.items():
                    if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 
                                 'pathname', 'filename', 'module', 'lineno', 
                                 'funcName', 'created', 'msecs', 'relativeCreated',
                                 'thread', 'threadName', 'processName', 'process',
                                 'getMessage', 'exc_info', 'exc_text', 'stack_info']:
                        log_entry[key] = value
            
            # Index the document
            index_name = f"{self.index_name}-{datetime.utcnow().strftime('%Y.%m.%d')}"
            self.es_client.index(
                index=index_name,
                body=log_entry
            )
            
        except Exception as e:
            # Don't let logging errors break the application
            print(f"Failed to log to Elasticsearch: {e}")

class AsyncLogHandler(logging.Handler):
    """Asynchronous logging handler using a queue"""
    
    def __init__(self, target_handler, buffer_size=1000):
        super().__init__()
        self.target_handler = target_handler
        self.buffer_size = buffer_size
        self.queue = queue.Queue(maxsize=buffer_size)
        self.thread = None
        self.shutdown_event = threading.Event()
        self._start_worker()
    
    def _start_worker(self):
        """Start the worker thread"""
        self.thread = threading.Thread(target=self._worker, daemon=True)
        self.thread.start()
    
    def _worker(self):
        """Worker thread that processes log records"""
        while not self.shutdown_event.is_set():
            try:
                # Get record with timeout
                record = self.queue.get(timeout=1.0)
                if record is None:  # Shutdown signal
                    break
                
                # Process the record
                self.target_handler.emit(record)
                self.queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Error in async log worker: {e}")
    
    def emit(self, record):
        """Emit log record to queue"""
        try:
            self.queue.put_nowait(record)
        except queue.Full:
            # Drop oldest record and add new one
            try:
                self.queue.get_nowait()
                self.queue.put_nowait(record)
            except queue.Empty:
                pass
    
    def close(self):
        """Close the handler and shutdown worker"""
        self.shutdown_event.set()
        self.queue.put(None)  # Shutdown signal
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5.0)
        super().close()

class CompressingRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """Rotating file handler that compresses old log files"""
    
    def __init__(self, filename, mode='a', maxBytes=0, backupCount=0, 
                 encoding=None, delay=False, compress=True):
        super().__init__(filename, mode, maxBytes, backupCount, encoding, delay)
        self.compress = compress
    
    def doRollover(self):
        """Override to add compression"""
        super().doRollover()
        
        if self.compress and self.backupCount > 0:
            # Compress the most recent backup
            backup_file = f"{self.baseFilename}.1"
            if os.path.exists(backup_file):
                compressed_file = f"{backup_file}.gz"
                
                try:
                    with open(backup_file, 'rb') as f_in:
                        with gzip.open(compressed_file, 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    
                    # Remove uncompressed file
                    os.remove(backup_file)
                    
                    # Rename compressed backups
                    for i in range(2, self.backupCount + 1):
                        old_name = f"{self.baseFilename}.{i}.gz"
                        new_name = f"{self.baseFilename}.{i + 1}.gz"
                        if os.path.exists(old_name):
                            if os.path.exists(new_name):
                                os.remove(new_name)
                            os.rename(old_name, new_name)
                    
                    # Rename the new compressed file
                    if os.path.exists(compressed_file):
                        final_name = f"{self.baseFilename}.1.gz"
                        if os.path.exists(final_name):
                            os.remove(final_name)
                        os.rename(compressed_file, final_name)
                        
                except Exception as e:
                    print(f"Failed to compress log file: {e}")

class FraudDetectionLogger:
    """Main logger class for the fraud detection system"""
    
    def __init__(self, config: Optional[LoggerConfig] = None):
        self.config = config or LoggerConfig()
        self.loggers = {}
        self.handlers = []
        self._setup_logging()
        
        # Security logger for audit trails
        self.security_logger = self._get_logger('security')
        self.fraud_logger = self._get_logger('fraud')
        self.performance_logger = self._get_logger('performance')
        
        # Metrics
        self.log_counts = {level.name: 0 for level in LogLevel}
        self.last_reset = datetime.utcnow()
    
    def _setup_logging(self):
        """Setup logging configuration"""
        # Create log directory
        self.config.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Configure structlog
        self._configure_structlog()
        
        # Setup handlers
        self._setup_handlers()
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(self.config.level)
        
        # Clear existing handlers
        root_logger.handlers.clear()
        
        # Add our handlers
        for handler in self.handlers:
            root_logger.addHandler(handler)
    
    def _configure_structlog(self):
        """Configure structlog processors"""
        processors = [
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
        ]
        
        if self.config.format == LogFormat.JSON.value:
            processors.append(structlog.processors.JSONRenderer())
        else:
            processors.append(structlog.dev.ConsoleRenderer())
        
        structlog.configure(
            processors=processors,
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
    
    def _setup_handlers(self):
        """Setup logging handlers"""
        # Console handler
        if self.config.enable_console:
            console_handler = logging.StreamHandler(sys.stdout)
            
            if self.config.format == LogFormat.JSON.value:
                console_handler.setFormatter(CustomJSONFormatter())
            else:
                console_handler.setFormatter(StructuredFormatter())
            
            console_handler.setLevel(self.config.level)
            self.handlers.append(console_handler)
        
        # File handlers
        if self.config.enable_file:
            self._setup_file_handlers()
        
        # Elasticsearch handler
        if self.config.enable_elasticsearch:
            try:
                es_handler = ElasticsearchHandler(
                    self.config.elasticsearch_hosts,
                    self.config.elasticsearch_index
                )
                es_handler.setLevel(logging.INFO)
                
                if self.config.async_logging:
                    es_handler = AsyncLogHandler(es_handler, self.config.buffer_size)
                
                self.handlers.append(es_handler)
            except Exception as e:
                print(f"Failed to setup Elasticsearch handler: {e}")
        
        # Syslog handler
        if self.config.enable_syslog:
            try:
                syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
                syslog_handler.setFormatter(
                    logging.Formatter('%(name)s[%(process)d]: %(levelname)s %(message)s')
                )
                self.handlers.append(syslog_handler)
            except Exception as e:
                print(f"Failed to setup syslog handler: {e}")
    
    def _setup_file_handlers(self):
        """Setup file-based logging handlers"""
        # Main application log
        app_log_file = self.config.log_dir / 'application.log'
        app_handler = CompressingRotatingFileHandler(
            app_log_file,
            maxBytes=self.config.max_file_size,
            backupCount=self.config.backup_count,
            compress=self.config.compress_logs
        )
        app_handler.setFormatter(CustomJSONFormatter())
        app_handler.setLevel(self.config.level)
        
        if self.config.async_logging:
            app_handler = AsyncLogHandler(app_handler, self.config.buffer_size)
        
        self.handlers.append(app_handler)
        
        # Error log (ERROR and CRITICAL only)
        error_log_file = self.config.log_dir / 'error.log'
        error_handler = CompressingRotatingFileHandler(
            error_log_file,
            maxBytes=self.config.max_file_size,
            backupCount=self.config.backup_count,
            compress=self.config.compress_logs
        )
        error_handler.setFormatter(CustomJSONFormatter())
        error_handler.setLevel(logging.ERROR)
        
        if self.config.async_logging:
            error_handler = AsyncLogHandler(error_handler, self.config.buffer_size)
        
        self.handlers.append(error_handler)
        
        # Security log
        security_log_file = self.config.log_dir / 'security.log'
        security_handler = CompressingRotatingFileHandler(
            security_log_file,
            maxBytes=self.config.max_file_size,
            backupCount=self.config.backup_count,
            compress=self.config.compress_logs
        )
        security_handler.setFormatter(CustomJSONFormatter())
        security_handler.setLevel(logging.INFO)
        
        # Add filter for security events only
        security_handler.addFilter(lambda record: record.name.startswith('security'))
        
        if self.config.async_logging:
            security_handler = AsyncLogHandler(security_handler, self.config.buffer_size)
        
        self.handlers.append(security_handler)
    
    def _get_logger(self, name: str) -> logging.Logger:
        """Get or create a logger with the given name"""
        if name not in self.loggers:
            self.loggers[name] = logging.getLogger(name)
        return self.loggers[name]
    
    def log_security_event(self, event_type: SecurityEventType, user_id: Optional[int] = None,
                          ip_address: Optional[str] = None, details: Optional[Dict] = None,
                          level: LogLevel = LogLevel.INFO) -> None:
        """Log a security event"""
        extra_data = {
            'category': LogCategory.SECURITY.value,
            'event_type': event_type.value,
            'user_id': user_id,
            'ip_address': ip_address,
            'details': details or {},
            'timestamp': datetime.utcnow().isoformat()
        }
        
        message = f"Security event: {event_type.value}"
        if user_id:
            message += f" (User: {user_id})"
        if ip_address:
            message += f" (IP: {ip_address})"
        
        self.security_logger.log(level.value, message, extra=extra_data)
        
        # Update metrics
        self.log_counts[level.name] += 1
    
    def log_fraud_event(self, transaction_id: str, risk_score: float, 
                       fraud_indicators: List[str], details: Optional[Dict] = None,
                       level: LogLevel = LogLevel.WARNING) -> None:
        """Log a fraud detection event"""
        extra_data = {
            'category': LogCategory.FRAUD.value,
            'transaction_id': transaction_id,
            'risk_score': risk_score,
            'fraud_indicators': fraud_indicators,
            'details': details or {},
            'timestamp': datetime.utcnow().isoformat()
        }
        
        message = f"Fraud event: Transaction {transaction_id} (Risk: {risk_score:.2f})"
        
        self.fraud_logger.log(level.value, message, extra=extra_data)
        self.log_counts[level.name] += 1
    
    def log_performance_metric(self, metric_name: str, value: float, 
                             unit: str = "ms", details: Optional[Dict] = None) -> None:
        """Log a performance metric"""
        extra_data = {
            'category': LogCategory.PERFORMANCE.value,
            'metric_name': metric_name,
            'value': value,
            'unit': unit,
            'details': details or {},
            'timestamp': datetime.utcnow().isoformat()
        }
        
        message = f"Performance metric: {metric_name} = {value} {unit}"
        
        self.performance_logger.info(message, extra=extra_data)
        self.log_counts[LogLevel.INFO.name] += 1
    
    def log_api_request(self, method: str, endpoint: str, status_code: int,
                       response_time: float, user_id: Optional[int] = None,
                       ip_address: Optional[str] = None) -> None:
        """Log an API request"""
        logger = self._get_logger('api')
        
        extra_data = {
            'category': LogCategory.API.value,
            'method': method,
            'endpoint': endpoint,
            'status_code': status_code,
            'response_time': response_time,
            'user_id': user_id,
            'ip_address': ip_address,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        level = LogLevel.ERROR if status_code >= 500 else LogLevel.INFO
        message = f"API {method} {endpoint} - {status_code} ({response_time:.2f}ms)"
        
        logger.log(level.value, message, extra=extra_data)
        self.log_counts[level.name] += 1
    
    def log_database_operation(self, operation: str, table: str, 
                             execution_time: float, affected_rows: int = 0,
                             error: Optional[str] = None) -> None:
        """Log a database operation"""
        logger = self._get_logger('database')
        
        extra_data = {
            'category': LogCategory.DATABASE.value,
            'operation': operation,
            'table': table,
            'execution_time': execution_time,
            'affected_rows': affected_rows,
            'error': error,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if error:
            level = LogLevel.ERROR
            message = f"Database {operation} on {table} failed: {error}"
        else:
            level = LogLevel.DEBUG
            message = f"Database {operation} on {table} ({execution_time:.2f}ms, {affected_rows} rows)"
        
        logger.log(level.value, message, extra=extra_data)
        self.log_counts[level.name] += 1
    
    def get_log_statistics(self) -> Dict[str, Any]:
        """Get logging statistics"""
        now = datetime.utcnow()
        time_since_reset = (now - self.last_reset).total_seconds()
        
        return {
            'log_counts': self.log_counts.copy(),
            'time_period_seconds': time_since_reset,
            'logs_per_second': {
                level: count / time_since_reset if time_since_reset > 0 else 0
                for level, count in self.log_counts.items()
            },
            'total_logs': sum(self.log_counts.values()),
            'last_reset': self.last_reset.isoformat()
        }
    
    def reset_statistics(self) -> None:
        """Reset logging statistics"""
        self.log_counts = {level.name: 0 for level in LogLevel}
        self.last_reset = datetime.utcnow()
    
    def close(self) -> None:
        """Close all handlers and cleanup"""
        for handler in self.handlers:
            handler.close()

# Decorators for automatic logging
def log_function_call(logger_name: str = 'application', 
                     level: LogLevel = LogLevel.DEBUG,
                     include_args: bool = False,
                     include_result: bool = False):
    """Decorator to log function calls"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger = logging.getLogger(logger_name)
            
            # Log function entry
            extra_data = {
                'function': func.__name__,
                'module': func.__module__,
                'category': LogCategory.DEBUG.value
            }
            
            if include_args:
                extra_data['args'] = str(args)
                extra_data['kwargs'] = str(kwargs)
            
            start_time = time.time()
            logger.log(level.value, f"Entering function: {func.__name__}", extra=extra_data)
            
            try:
                result = func(*args, **kwargs)
                
                # Log successful completion
                execution_time = (time.time() - start_time) * 1000
                extra_data['execution_time_ms'] = execution_time
                extra_data['success'] = True
                
                if include_result:
                    extra_data['result'] = str(result)
                
                logger.log(level.value, f"Function completed: {func.__name__}", extra=extra_data)
                
                return result
                
            except Exception as e:
                # Log exception
                execution_time = (time.time() - start_time) * 1000
                extra_data['execution_time_ms'] = execution_time
                extra_data['success'] = False
                extra_data['error'] = str(e)
                extra_data['exception_type'] = type(e).__name__
                
                logger.error(f"Function failed: {func.__name__}", extra=extra_data, exc_info=True)
                raise
        
        return wrapper
    return decorator

def log_performance(logger_name: str = 'performance', 
                   threshold_ms: float = 1000.0):
    """Decorator to log performance metrics"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            
            try:
                result = func(*args, **kwargs)
                execution_time = (time.time() - start_time) * 1000
                
                # Log if execution time exceeds threshold
                if execution_time > threshold_ms:
                    logger = logging.getLogger(logger_name)
                    extra_data = {
                        'function': func.__name__,
                        'module': func.__module__,
                        'execution_time_ms': execution_time,
                        'threshold_ms': threshold_ms,
                        'category': LogCategory.PERFORMANCE.value
                    }
                    
                    logger.warning(
                        f"Slow function execution: {func.__name__} took {execution_time:.2f}ms",
                        extra=extra_data
                    )
                
                return result
                
            except Exception as e:
                execution_time = (time.time() - start_time) * 1000
                logger = logging.getLogger(logger_name)
                
                extra_data = {
                    'function': func.__name__,
                    'module': func.__module__,
                    'execution_time_ms': execution_time,
                    'error': str(e),
                    'category': LogCategory.ERROR.value
                }
                
                logger.error(
                    f"Function failed after {execution_time:.2f}ms: {func.__name__}",
                    extra=extra_data,
                    exc_info=True
                )
                raise
        
        return wrapper
    return decorator

@contextmanager
def log_context(logger_name: str, context_name: str, **context_data):
    """Context manager for logging with additional context"""
    logger = logging.getLogger(logger_name)
    
    # Add context to all log records in this context
    old_factory = logging.getLogRecordFactory()
    
    def record_factory(*args, **kwargs):
        record = old_factory(*args, **kwargs)
        record.context_name = context_name
        for key, value in context_data.items():
            setattr(record, key, value)
        return record
    
    logging.setLogRecordFactory(record_factory)
    
    try:
        logger.info(f"Entering context: {context_name}", extra=context_data)
        yield logger
        logger.info(f"Exiting context: {context_name}", extra=context_data)
    except Exception as e:
        logger.error(f"Context failed: {context_name}", extra={
            **context_data,
            'error': str(e),
            'exception_type': type(e).__name__
        }, exc_info=True)
        raise
    finally:
        logging.setLogRecordFactory(old_factory)

# Global logger instance
fraud_logger = FraudDetectionLogger()

# Convenience functions
def get_logger(name: str) -> logging.Logger:
    """Get a logger instance"""
    return fraud_logger._get_logger(name)

def log_security_event(event_type: SecurityEventType, **kwargs):
    """Log a security event"""
    return fraud_logger.log_security_event(event_type, **kwargs)

def log_fraud_event(transaction_id: str, risk_score: float, fraud_indicators: List[str], **kwargs):
    """Log a fraud event"""
    return fraud_logger.log_fraud_event(transaction_id, risk_score, fraud_indicators, **kwargs)

def log_performance_metric(metric_name: str, value: float, **kwargs):
    """Log a performance metric"""
    return fraud_logger.log_performance_metric(metric_name, value, **kwargs)

# Export public API
__all__ = [
    "LogLevel",
    "LogCategory", 
    "LogFormat",
    "SecurityEventType",
    "LoggerConfig",
    "FraudDetectionLogger",
    "fraud_logger",
    "get_logger",
    "log_security_event",
    "log_fraud_event",
    "log_performance_metric",
    "log_function_call",
    "log_performance",
    "log_context"
]

# Initialize logging
fraud_logger.security_logger.info("Logging system initialized", extra={
    'category': LogCategory.SYSTEM.value,
    'component': 'logger',
    'version': settings.app_version
})