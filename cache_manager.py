"""
Cache Manager - Zaawansowany system cache'owania z Redis i fallback
"""
import json
import hashlib
import logging
from typing import Any, Optional, Dict, List, Callable
from datetime import datetime, timedelta
from functools import wraps
import pickle
import zlib

try:
    import redis  # type: ignore
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None

try:
    from flask import current_app, g  # type: ignore
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    current_app = None
    g = None


class CacheManager:
    """Zaawansowany menedżer cache'owania z Redis i fallback"""
    
    def __init__(self, app=None):
        self.app = app
        self.redis_client = None
        self.memory_cache = {}  # Fallback cache w pamięci
        self.cache_stats = {
            'hits': 0,
            'misses': 0,
            'sets': 0,
            'deletes': 0
        }
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Inicjalizacja cache managera z aplikacją Flask"""
        self.app = app
        
        # Konfiguracja Redis
        if REDIS_AVAILABLE and redis and app.config.get('REDIS_URL'):
            try:
                self.redis_client = redis.from_url(
                    app.config['REDIS_URL'],
                    decode_responses=False,  # Zachowujemy binarne dane
                    socket_connect_timeout=5,
                    socket_timeout=5,
                    retry_on_timeout=True
                )
                # Test połączenia
                self.redis_client.ping()
                app.logger.info("Redis cache initialized successfully")
            except Exception as e:
                app.logger.warning(f"Redis cache initialization failed: {e}")
                self.redis_client = None
        
        if not self.redis_client:
            app.logger.info("Using in-memory cache fallback")
    
    def _generate_key(self, prefix: str, *args, **kwargs) -> str:
        """Generuje unikalny klucz cache"""
        key_data = {
            'prefix': prefix,
            'args': args,
            'kwargs': sorted(kwargs.items())
        }
        key_str = json.dumps(key_data, sort_keys=True)
        return f"mobywatel:{hashlib.md5(key_str.encode()).hexdigest()}"
    
    def _serialize_data(self, data: Any) -> bytes:
        """Serializuje dane do binarnego formatu"""
        try:
            # Kompresja danych
            serialized = pickle.dumps(data, protocol=pickle.HIGHEST_PROTOCOL)
            compressed = zlib.compress(serialized)
            return compressed
        except Exception as e:
            logging.error(f"Serialization error: {e}")
            # Fallback do JSON
            return json.dumps(data).encode()
    
    def _deserialize_data(self, data: bytes) -> Any:
        """Deserializuje dane z binarnego formatu"""
        try:
            # Próba dekompresji
            decompressed = zlib.decompress(data)
            return pickle.loads(decompressed)
        except Exception:
            # Fallback do JSON
            return json.loads(data.decode())
    
    def get(self, key: str, default: Any = None) -> Any:
        """Pobiera dane z cache"""
        try:
            if self.redis_client:
                # Próba Redis
                data = self.redis_client.get(key)
                if data is not None:
                    self.cache_stats['hits'] += 1
                    return self._deserialize_data(data)
            
            # Fallback do pamięci
            if key in self.memory_cache:
                item = self.memory_cache[key]
                if item['expires_at'] > datetime.now():
                    self.cache_stats['hits'] += 1
                    return item['data']
                else:
                    # Usuń wygasły element
                    del self.memory_cache[key]
            
            self.cache_stats['misses'] += 1
            return default
            
        except Exception as e:
            logging.error(f"Cache get error: {e}")
            self.cache_stats['misses'] += 1
            return default
    
    def set(self, key: str, value: Any, timeout: int = 300) -> bool:
        """Zapisuje dane do cache"""
        try:
            serialized_data = self._serialize_data(value)
            
            if self.redis_client:
                # Próba Redis
                success = self.redis_client.setex(key, timeout, serialized_data)
                if success:
                    self.cache_stats['sets'] += 1
                    return True
            
            # Fallback do pamięci
            expires_at = datetime.now() + timedelta(seconds=timeout)
            self.memory_cache[key] = {
                'data': value,
                'expires_at': expires_at
            }
            self.cache_stats['sets'] += 1
            return True
            
        except Exception as e:
            logging.error(f"Cache set error: {e}")
            return False
    
    def delete(self, key: str) -> bool:
        """Usuwa dane z cache"""
        try:
            if self.redis_client:
                self.redis_client.delete(key)
            
            if key in self.memory_cache:
                del self.memory_cache[key]
            
            self.cache_stats['deletes'] += 1
            return True
            
        except Exception as e:
            logging.error(f"Cache delete error: {e}")
            return False
    
    def clear(self, pattern: str = "mobywatel:*") -> bool:
        """Czyści cache według wzorca"""
        try:
            if self.redis_client:
                keys = self.redis_client.keys(pattern)
                if keys:
                    self.redis_client.delete(*keys)
            
            # Czyść pamięć cache
            keys_to_delete = [k for k in self.memory_cache.keys() if k.startswith("mobywatel:")]
            for key in keys_to_delete:
                del self.memory_cache[key]
            
            return True
            
        except Exception as e:
            logging.error(f"Cache clear error: {e}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Zwraca statystyki cache"""
        total_requests = self.cache_stats['hits'] + self.cache_stats['misses']
        hit_rate = (self.cache_stats['hits'] / total_requests * 100) if total_requests > 0 else 0
        
        return {
            'hits': self.cache_stats['hits'],
            'misses': self.cache_stats['misses'],
            'sets': self.cache_stats['sets'],
            'deletes': self.cache_stats['deletes'],
            'hit_rate': round(hit_rate, 2),
            'memory_cache_size': len(self.memory_cache),
            'redis_available': self.redis_client is not None
        }
    
    def invalidate_pattern(self, pattern: str) -> int:
        """Unieważnia cache według wzorca"""
        try:
            count = 0
            
            if self.redis_client:
                keys = self.redis_client.keys(pattern)
                if keys:
                    count += self.redis_client.delete(*keys)
            
            # Unieważnij w pamięci cache
            keys_to_delete = [k for k in self.memory_cache.keys() if pattern in k]
            for key in keys_to_delete:
                del self.memory_cache[key]
                count += 1
            
            return count
            
        except Exception as e:
            logging.error(f"Cache invalidate error: {e}")
            return 0


# Globalna instancja cache managera
cache_manager = CacheManager()


def cached(timeout: int = 300, key_prefix: str = "func"):
    """
    Dekorator do cache'owania funkcji
    
    Args:
        timeout: Czas ważności cache w sekundach
        key_prefix: Prefiks klucza cache
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generuj klucz cache
            cache_key = cache_manager._generate_key(key_prefix, func.__name__, *args, **kwargs)
            
            # Próba pobrania z cache
            cached_result = cache_manager.get(cache_key)
            if cached_result is not None:
                return cached_result
            
            # Wykonaj funkcję i zapisz wynik
            result = func(*args, **kwargs)
            cache_manager.set(cache_key, result, timeout)
            
            return result
        return wrapper
    return decorator


def cache_invalidate(pattern: str):
    """
    Dekorator do unieważniania cache po wykonaniu funkcji
    
    Args:
        pattern: Wzorzec kluczy do unieważnienia
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            cache_manager.invalidate_pattern(pattern)
            return result
        return wrapper
    return decorator


# Specjalizowane funkcje cache dla różnych typów danych
class UserCache:
    """Cache dla danych użytkowników"""
    
    @staticmethod
    @cached(timeout=300, key_prefix="user")
    def get_user_info(username: str) -> Optional[Dict]:
        """Cache dla informacji o użytkowniku"""
        from models import User
        user = User.query.filter_by(username=username).first()
        if user:
            return {
                'username': user.username,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'last_login': user.last_login.isoformat() if user.last_login else None,
                'is_active': user.is_active,
                'hubert_coins': user.hubert_coins
            }
        return None
    
    @staticmethod
    @cache_invalidate("mobywatel:user:*")
    def invalidate_user_cache(username: str):
        """Unieważnia cache użytkownika"""
        cache_manager.invalidate_pattern(f"mobywatel:user:*{username}*")


class StatsCache:
    """Cache dla statystyk"""
    
    @staticmethod
    @cached(timeout=60, key_prefix="stats")
    def get_overall_stats() -> Dict:
        """Cache dla ogólnych statystyk"""
        try:
            from models import User, File, db
            from sqlalchemy import func  # type: ignore
            
            total_users = User.query.count()
            total_files = File.query.count()
            total_size = db.session.query(func.sum(File.size)).scalar() or 0
            
            return {
                'total_users': total_users,
                'total_files': total_files,
                'total_size': total_size
            }
        except ImportError:
            return {
                'total_users': 0,
                'total_files': 0,
                'total_size': 0
            }
    
    @staticmethod
    @cached(timeout=300, key_prefix="user_stats")
    def get_user_stats(username: str) -> Dict:
        """Cache dla statystyk użytkownika"""
        try:
            from models import File
            from sqlalchemy import func  # type: ignore
            
            files = File.query.filter_by(user_username=username).all()
            total_size = sum(f.size for f in files)
            
            return {
                'file_count': len(files),
                'total_size': total_size,
                'last_modified': max(f.modified_at for f in files).isoformat() if files else None
            }
        except ImportError:
            return {
                'file_count': 0,
                'total_size': 0,
                'last_modified': None
            }


class AnnouncementCache:
    """Cache dla ogłoszeń"""
    
    @staticmethod
    @cached(timeout=300, key_prefix="announcements")
    def get_active_announcements() -> List[Dict]:
        """Cache dla aktywnych ogłoszeń"""
        from models import Announcement
        from datetime import datetime
        
        announcements = Announcement.query.filter(
            Announcement.is_active,
            (Announcement.expires_at.is_(None)) | (Announcement.expires_at > datetime.now())
        ).order_by(Announcement.created_at.desc()).all()
        
        return [
            {
                'id': a.id,
                'title': a.title,
                'message': a.message,
                'type': a.type,
                'created_at': a.created_at.isoformat() if a.created_at else None
            }
            for a in announcements
        ]
