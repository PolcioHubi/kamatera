"""
Database Optimization - Indeksy i optymalizacje bazy danych
"""
try:
    from sqlalchemy import Index, text  # type: ignore
    SQLALCHEMY_AVAILABLE = True
except ImportError:
    SQLALCHEMY_AVAILABLE = False
    Index = None
    text = None

try:
    from models import db, User, File, AccessKey, Announcement, Notification
    MODELS_AVAILABLE = True
except ImportError:
    MODELS_AVAILABLE = False
    db = None
    User = None
    File = None
    AccessKey = None
    Announcement = None
    Notification = None


def create_database_indexes():
    """Tworzy indeksy dla optymalizacji zapytań"""
    
    if not SQLALCHEMY_AVAILABLE or not MODELS_AVAILABLE:
        print("SQLAlchemy or models not available, skipping index creation")
        return []
    
    # Indeksy dla tabeli User
    indexes = []
    
    if User is not None and Index is not None:
        indexes.extend([
            # Indeks dla wyszukiwania użytkowników po nazwie użytkownika
            Index('idx_user_username', User.username),
            
            # Indeks dla wyszukiwania aktywnych użytkowników
            Index('idx_user_active', User.is_active),
            
            # Indeks dla sortowania po dacie utworzenia
            Index('idx_user_created_at', User.created_at),
            
            # Indeks dla ostatniego logowania
            Index('idx_user_last_login', User.last_login),
            
            # Indeks złożony dla często używanych kombinacji
            Index('idx_user_username_active', User.username, User.is_active),
            
            # Indeks dla tokenów resetowania hasła
            Index('idx_user_password_reset_token', User.password_reset_token),
            
            # Indeks dla tokenów odzyskiwania
            Index('idx_user_recovery_token', User.recovery_token),
            
            # Indeks dla kluczy dostępu
            Index('idx_user_access_key_used', User.access_key_used),
            
            # Indeks dla Hubert Coins
            Index('idx_user_hubert_coins', User.hubert_coins),
        ])
    
    if File is not None and Index is not None:
        indexes.extend([
            # Indeksy dla tabeli File
            Index('idx_file_user_username', File.user_username),
            Index('idx_file_filename', File.filename),
            Index('idx_file_modified_at', File.modified_at),
            Index('idx_file_hash', File.file_hash),
            
            # Indeks złożony dla plików użytkownika
            Index('idx_file_user_modified', File.user_username, File.modified_at),
        ])
    
    if AccessKey is not None and Index is not None:
        indexes.extend([
            # Indeksy dla tabeli AccessKey
            Index('idx_access_key_key', AccessKey.key),
            Index('idx_access_key_active', AccessKey.is_active),
            Index('idx_access_key_expires_at', AccessKey.expires_at),
            Index('idx_access_key_created_at', AccessKey.created_at),
            
            # Indeks złożony dla aktywnych kluczy
            Index('idx_access_key_active_expires', AccessKey.is_active, AccessKey.expires_at),
        ])
    
    if Announcement is not None and Index is not None:
        indexes.extend([
            # Indeksy dla tabeli Announcement
            Index('idx_announcement_active', Announcement.is_active),
            Index('idx_announcement_expires_at', Announcement.expires_at),
            Index('idx_announcement_created_at', Announcement.created_at),
            Index('idx_announcement_type', Announcement.type),
            
            # Indeks złożony dla aktywnych ogłoszeń
            Index('idx_announcement_active_expires', Announcement.is_active, Announcement.expires_at),
        ])
    
    if Notification is not None:
        indexes.extend([
            # Indeksy dla tabeli Notification
            Index('idx_notification_user_id', Notification.user_id),
            Index('idx_notification_is_read', Notification.is_read),
            Index('idx_notification_created_at', Notification.created_at),
            
            # Indeks złożony dla nieprzeczytanych powiadomień
            Index('idx_notification_user_read', Notification.user_id, Notification.is_read),
        ])
    
    return indexes


def optimize_database():
    """Wykonuje optymalizacje bazy danych"""
    
    if not SQLALCHEMY_AVAILABLE or not MODELS_AVAILABLE or db is None:
        print("SQLAlchemy, models or database not available, skipping optimization")
        return
    
    # Twórz indeksy
    indexes = create_database_indexes()
    
    for index in indexes:
        try:
            # Sprawdź czy indeks już istnieje
            index_name = index.name
            result = db.session.execute(text(
                "SELECT name FROM sqlite_master WHERE type='index' AND name=:name"
            ), {"name": index_name})
            
            if not result.fetchone():
                # Indeks nie istnieje, utwórz go
                index.create(db.engine)
                print(f"Created index: {index_name}")
            else:
                print(f"Index already exists: {index_name}")
                
        except Exception as e:
            print(f"Error creating index {index.name}: {e}")
    
    # Analizuj bazę danych dla optymalizacji
    try:
        db.session.execute(text("ANALYZE"))
        print("Database analyzed for optimization")
    except Exception as e:
        print(f"Error analyzing database: {e}")
    
    # Ustaw pragma dla lepszej wydajności SQLite
    pragma_settings = [
        "PRAGMA journal_mode=WAL",  # Write-Ahead Logging
        "PRAGMA synchronous=NORMAL",  # Balans między bezpieczeństwem a wydajnością
        "PRAGMA cache_size=10000",  # Zwiększ cache
        "PRAGMA temp_store=MEMORY",  # Tymczasowe tabele w pamięci
        "PRAGMA mmap_size=268435456",  # Memory-mapped I/O (256MB)
        "PRAGMA optimize",  # Optymalizuj bazę
    ]
    
    for pragma in pragma_settings:
        try:
            db.session.execute(text(pragma))
            print(f"Applied: {pragma}")
        except Exception as e:
            print(f"Error applying {pragma}: {e}")


def get_database_stats():
    """Zwraca statystyki bazy danych"""
    if not SQLALCHEMY_AVAILABLE or not MODELS_AVAILABLE or db is None:
        print("SQLAlchemy, models or database not available, returning empty stats")
        return {}
    
    try:
        # Statystyki tabel
        tables = ['users', 'files', 'access_keys', 'announcements', 'notifications']
        stats = {}
        
        for table in tables:
            # Liczba rekordów
            count_result = db.session.execute(text(f"SELECT COUNT(*) FROM {table}"))
            count = count_result.scalar()
            
            # Rozmiar tabeli
            size_result = db.session.execute(text(
                f"SELECT SUM(pgsize) FROM dbstat WHERE name='{table}'"
            ))
            size = size_result.scalar() or 0
            
            stats[table] = {
                'count': count,
                'size_bytes': size
            }
        
        # Statystyki indeksów
        index_result = db.session.execute(text(
            "SELECT name, type FROM sqlite_master WHERE type='index'"
        ))
        indexes = [{'name': row[0], 'type': row[1]} for row in index_result.fetchall()]
        
        # Statystyki cache
        cache_result = db.session.execute(text("PRAGMA cache_stats"))
        cache_stats = dict(cache_result.fetchall())
        
        return {
            'tables': stats,
            'indexes': indexes,
            'cache_stats': cache_stats
        }
        
    except Exception as e:
        print(f"Error getting database stats: {e}")
        return {}


def vacuum_database():
    """Wykonuje VACUUM na bazie danych"""
    if not SQLALCHEMY_AVAILABLE or not MODELS_AVAILABLE or db is None:
        print("SQLAlchemy, models or database not available, skipping vacuum")
        return False
    
    try:
        db.session.execute(text("VACUUM"))
        print("Database vacuumed successfully")
        return True
    except Exception as e:
        print(f"Error vacuuming database: {e}")
        return False


def reindex_database():
    """Przebudowuje wszystkie indeksy"""
    if not SQLALCHEMY_AVAILABLE or not MODELS_AVAILABLE or db is None:
        print("SQLAlchemy, models or database not available, skipping reindex")
        return False
    
    try:
        db.session.execute(text("REINDEX"))
        print("Database reindexed successfully")
        return True
    except Exception as e:
        print(f"Error reindexing database: {e}")
        return False


# Funkcje pomocnicze do monitorowania wydajności
def get_slow_queries():
    """Zwraca listę wolnych zapytań (wymaga włączenia query logging)"""
    # To wymaga dodatkowej konfiguracji do logowania zapytań
    return []


def optimize_specific_queries():
    """Optymalizuje konkretne zapytania"""
    
    # Optymalizacja zapytań dla statystyk użytkowników
    optimized_queries = {
        'user_stats': """
            SELECT 
                u.username,
                COUNT(f.id) as file_count,
                COALESCE(SUM(f.size), 0) as total_size,
                MAX(f.modified_at) as last_file_modified
            FROM users u
            LEFT JOIN files f ON u.username = f.user_username
            WHERE u.is_active = 1
            GROUP BY u.username
            ORDER BY total_size DESC
        """,
        
        'active_announcements': """
            SELECT id, title, message, type, created_at
            FROM announcements
            WHERE is_active = 1 
            AND (expires_at IS NULL OR expires_at > datetime('now'))
            ORDER BY created_at DESC
        """,
        
        'user_notifications': """
            SELECT id, message, is_read, created_at
            FROM notifications
            WHERE user_id = :user_id
            ORDER BY created_at DESC
            LIMIT :limit
        """
    }
    
    return optimized_queries


# Funkcje do zarządzania połączeniami
def get_connection_pool_stats():
    """Zwraca statystyki puli połączeń"""
    if not SQLALCHEMY_AVAILABLE or not MODELS_AVAILABLE or db is None:
        print("SQLAlchemy, models or database not available, returning empty pool stats")
        return {}
    
    try:
        engine = db.engine
        pool = engine.pool
        
        return {
            'pool_size': pool.size(),
            'checked_in': pool.checkedin(),
            'checked_out': pool.checkedout(),
            'overflow': pool.overflow(),
            'invalid': pool.invalid()
        }
    except Exception as e:
        print(f"Error getting connection pool stats: {e}")
        return {}


def reset_connection_pool():
    """Resetuje pulę połączeń"""
    if not SQLALCHEMY_AVAILABLE or not MODELS_AVAILABLE or db is None:
        print("SQLAlchemy, models or database not available, skipping pool reset")
        return False
    
    try:
        engine = db.engine
        engine.dispose()
        print("Connection pool reset successfully")
        return True
    except Exception as e:
        print(f"Error resetting connection pool: {e}")
        return False
