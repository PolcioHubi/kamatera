"""
Celery Configuration
"""
import os

try:
    from celery import Celery  # type: ignore
    CELERY_AVAILABLE = True
except ImportError:
    CELERY_AVAILABLE = False
    Celery = None

def make_celery_config():
    """Create Celery configuration"""
    
    # Broker settings
    broker_url = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/1')
    result_backend = os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/2')
    
    # Task settings
    task_serializer = 'json'
    accept_content = ['json']
    result_serializer = 'json'
    timezone = 'Europe/Warsaw'
    enable_utc = True
    
    # Worker settings
    worker_prefetch_multiplier = 1
    worker_max_tasks_per_child = 1000
    worker_disable_rate_limits = False
    
    # Task routing
    task_routes = {
        'tasks.process_document_generation': {'queue': 'documents'},
        'tasks.process_file_upload': {'queue': 'files'},
        'tasks.cleanup_expired_data': {'queue': 'maintenance'},
        'tasks.generate_backup': {'queue': 'backup'},
    }
    
    # Task time limits
    task_soft_time_limit = 300  # 5 minutes
    task_time_limit = 600       # 10 minutes
    
    # Result settings
    result_expires = 3600  # 1 hour
    
    # Beat schedule
    beat_schedule = {
        'cleanup-expired-data': {
            'task': 'tasks.cleanup_expired_data',
            'schedule': 86400.0,  # Daily
        },
        'generate-daily-backup': {
            'task': 'tasks.generate_backup',
            'schedule': 86400.0,  # Daily
            'args': ('full',),
        },
    }
    
    return {
        'broker_url': broker_url,
        'result_backend': result_backend,
        'task_serializer': task_serializer,
        'accept_content': accept_content,
        'result_serializer': result_serializer,
        'timezone': timezone,
        'enable_utc': enable_utc,
        'worker_prefetch_multiplier': worker_prefetch_multiplier,
        'worker_max_tasks_per_child': worker_max_tasks_per_child,
        'worker_disable_rate_limits': worker_disable_rate_limits,
        'task_routes': task_routes,
        'task_soft_time_limit': task_soft_time_limit,
        'task_time_limit': task_time_limit,
        'result_expires': result_expires,
        'beat_schedule': beat_schedule,
    }
