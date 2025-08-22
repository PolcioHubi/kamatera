"""
Async Tasks - Asynchroniczne operacje z Celery
"""
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import hashlib
from pathlib import Path

try:
    from celery import Celery, current_task  # type: ignore
    from celery.utils.log import get_task_logger  # type: ignore
    CELERY_AVAILABLE = True
except ImportError:
    CELERY_AVAILABLE = False
    Celery = None
    current_task = None
    get_task_logger = None

from models import db, Announcement
from cache_manager import cache_manager


# Konfiguracja Celery
def make_celery(app):
    """Tworzy instancję Celery dla aplikacji Flask"""
    if not CELERY_AVAILABLE or not Celery:
        return None
    
    celery = Celery(
        app.import_name,
        backend=app.config.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/1'),
        broker=app.config.get('CELERY_BROKER_URL', 'redis://localhost:6379/0')
    )
    
    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)
    
    celery.Task = ContextTask
    return celery


# Inicjalizacja Celery (będzie ustawiona w app.py)
celery_app = None

# Import celery config
logger = get_task_logger(__name__) if CELERY_AVAILABLE and get_task_logger else logging.getLogger(__name__)


def get_celery_app():
    """Pobiera instancję Celery lub zwraca None"""
    return celery_app


def task_decorator(name):
    """Dekorator dla zadań Celery z obsługą braku Celery"""
    def decorator(func):
        if CELERY_AVAILABLE and celery_app is not None:
            return celery_app.task(bind=True, name=name)(func)
        else:
            # Fallback - zwróć funkcję bez dekoracji
            return func
    return decorator


@task_decorator('tasks.process_document_generation')
def process_document_generation(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Asynchroniczne generowanie dokumentu
    
    Args:
        user_data: Dane użytkownika do przetworzenia
        
    Returns:
        Dict z wynikiem operacji
    """
    try:
        # Aktualizuj status zadania
        self.update_state(
            state='PROGRESS',
            meta={'current': 0, 'total': 100, 'status': 'Rozpoczynanie generowania dokumentu...'}
        )
        
        username = user_data.get('user_name')
        if not username:
            raise ValueError("Brak nazwy użytkownika")
        
        # Krok 1: Walidacja danych
        self.update_state(
            state='PROGRESS',
            meta={'current': 10, 'total': 100, 'status': 'Walidacja danych...'}
        )
        
        required_fields = ['imie', 'nazwisko', 'pesel', 'data_urodzenia']
        for field in required_fields:
            if not user_data.get(field):
                raise ValueError(f"Brak wymaganego pola: {field}")
        
        # Krok 2: Przygotowanie katalogów
        self.update_state(
            state='PROGRESS',
            meta={'current': 20, 'total': 100, 'status': 'Przygotowanie katalogów...'}
        )
        
        user_folder = Path(f"user_data/{username}")
        files_folder = user_folder / "files"
        files_folder.mkdir(parents=True, exist_ok=True)
        
        # Krok 3: Generowanie dokumentu
        self.update_state(
            state='PROGRESS',
            meta={'current': 40, 'total': 100, 'status': 'Generowanie dokumentu HTML...'}
        )
        
        from app import replace_html_data
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            raise ImportError("BeautifulSoup4 jest wymagane do generowania dokumentów")
        
        # Wczytaj szablon
        template_path = Path("pasted_content.txt")
        if not template_path.exists():
            raise FileNotFoundError("Szablon dokumentu nie został znaleziony")
        
        with open(template_path, 'r', encoding='utf-8') as f:
            soup = BeautifulSoup(f.read(), 'html.parser')
        
        # Zastąp dane w szablonie
        modified_soup = replace_html_data(soup, user_data)
        
        # Krok 4: Zapisz dokument
        self.update_state(
            state='PROGRESS',
            meta={'current': 70, 'total': 100, 'status': 'Zapisywanie dokumentu...'}
        )
        
        output_filename = "dowodnowy.html"
        output_filepath = files_folder / output_filename
        
        with open(output_filepath, 'w', encoding='utf-8') as f:
            f.write(str(modified_soup))
        
        # Krok 5: Aktualizuj bazę danych
        self.update_state(
            state='PROGRESS',
            meta={'current': 90, 'total': 100, 'status': 'Aktualizacja bazy danych...'}
        )
        
        from services import StatisticsService
        stats_service = StatisticsService()
        
        # Dodaj metadane pliku do bazy
        file_size = output_filepath.stat().st_size
        file_hash = hashlib.sha256(output_filepath.read_bytes()).hexdigest()
        
        stats_service.add_or_update_file(
            username=username,
            filename=output_filename,
            filepath=str(output_filepath),
            size=file_size,
            file_hash=file_hash
        )
        
        # Krok 6: Zakończ
        self.update_state(
            state='SUCCESS',
            meta={'current': 100, 'total': 100, 'status': 'Dokument wygenerowany pomyślnie'}
        )
        
        # Unieważnij cache
        cache_manager.invalidate_pattern(f"mobywatel:user:*{username}*")
        
        return {
            'success': True,
            'message': 'Dokument został wygenerowany pomyślnie',
            'file_path': str(output_filepath),
            'file_size': file_size,
            'file_hash': file_hash
        }
        
    except Exception as e:
        logger.error(f"Error in document generation: {e}")
        self.update_state(
            state='FAILURE',
            meta={'error': str(e)}
        )
        return {
            'success': False,
            'error': str(e)
        }


@task_decorator('tasks.process_file_upload')
def process_file_upload(self, file_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Asynchroniczne przetwarzanie uploadu pliku
    
    Args:
        file_data: Dane pliku do przetworzenia
        
    Returns:
        Dict z wynikiem operacji
    """
    try:
        self.update_state(
            state='PROGRESS',
            meta={'current': 0, 'total': 100, 'status': 'Rozpoczynanie przetwarzania pliku...'}
        )
        
        username = file_data.get('username')
        file_content = file_data.get('content')
        filename = file_data.get('filename')
        # Initialize variables to avoid unbound references in later branches
        file_path: Optional[Path] = None
        file_size = 0
        file_hash = ""
        
        if not all([username, file_content, filename]):
            raise ValueError("Brak wymaganych danych pliku")
        
        # Krok 1: Walidacja pliku
        self.update_state(
            state='PROGRESS',
            meta={'current': 20, 'total': 100, 'status': 'Walidacja pliku...'}
        )
        
        # Sprawdź rozmiar
        if file_content and len(file_content) > 10 * 1024 * 1024:  # 10MB
            raise ValueError("Plik jest za duży")
        
        # Sprawdź typ MIME (opcjonalnie)
        try:
            import magic  # type: ignore
            if file_content:
                mime_type = magic.from_buffer(file_content, mime=True)
                allowed_types = ['image/jpeg', 'image/png', 'image/gif']
                
                if mime_type not in allowed_types:
                    raise ValueError(f"Nieprawidłowy typ pliku: {mime_type}")
        except ImportError:
            # Jeśli magic nie jest dostępne, pomiń walidację typu MIME
            pass
        
        # Krok 2: Zapisz plik
        self.update_state(
            state='PROGRESS',
            meta={'current': 60, 'total': 100, 'status': 'Zapisywanie pliku...'}
        )
        
        user_folder = Path(f"user_data/{username}/files")
        user_folder.mkdir(parents=True, exist_ok=True)
        
        if filename:
            target_path = user_folder / filename
            with open(target_path, 'wb') as f:
                if file_content:
                    f.write(file_content)
            # Keep for later response and DB update
            file_path = target_path
            
            # Krok 3: Aktualizuj bazę danych
            self.update_state(
                state='PROGRESS',
                meta={'current': 80, 'total': 100, 'status': 'Aktualizacja bazy danych...'}
            )
            
            from services import StatisticsService
            stats_service = StatisticsService()
            
            file_size = len(file_content) if file_content else 0
            file_hash = hashlib.sha256(file_content).hexdigest() if file_content else ""
            
            if username and filename:
                stats_service.add_or_update_file(
                    username=username,
                    filename=filename,
                    filepath=str(file_path),
                    size=file_size,
                    file_hash=file_hash
                )
        
        # Krok 4: Zakończ
        self.update_state(
            state='SUCCESS',
            meta={'current': 100, 'total': 100, 'status': 'Plik przetworzony pomyślnie'}
        )
        
        # Unieważnij cache
        cache_manager.invalidate_pattern(f"mobywatel:user:*{username}*")
        
        # Prepare response data with safe defaults
        result_file_path = ""
        result_file_size = 0
        result_file_hash = ""
        
        if filename and file_content:
            # Variables initialized at the top ensure safe defaults
            if file_path:
                result_file_path = str(file_path)
            result_file_size = file_size
            result_file_hash = file_hash
            
            return {
                'success': True,
                'message': 'Plik został przetworzony pomyślnie',
                'file_path': result_file_path,
                'file_size': result_file_size,
                'file_hash': result_file_hash
            }
        else:
            return {
                'success': False,
                'error': 'Brak wymaganych danych pliku'
            }
        
    except Exception as e:
        logger.error(f"Error in file upload processing: {e}")
        self.update_state(
            state='FAILURE',
            meta={'error': str(e)}
        )
        return {
            'success': False,
            'error': str(e)
        }


@task_decorator('tasks.cleanup_expired_data')
def cleanup_expired_data(self) -> Dict[str, Any]:
    """
    Asynchroniczne czyszczenie wygasłych danych
    
    Returns:
        Dict z wynikiem operacji
    """
    try:
        self.update_state(
            state='PROGRESS',
            meta={'current': 0, 'total': 100, 'status': 'Rozpoczynanie czyszczenia...'}
        )
        
        cleaned_items = {
            'expired_announcements': 0,
            'expired_access_keys': 0,
            'old_logs': 0,
            'temp_files': 0
        }
        
        # Krok 1: Wyczyść wygasłe ogłoszenia
        self.update_state(
            state='PROGRESS',
            meta={'current': 25, 'total': 100, 'status': 'Czyszczenie wygasłych ogłoszeń...'}
        )
        
        expired_announcements = Announcement.query.filter(
            Announcement.expires_at < datetime.now(),
            Announcement.is_active
        ).all()
        
        for announcement in expired_announcements:
            announcement.is_active = False
            cleaned_items['expired_announcements'] += 1
        
        # Krok 2: Wyczyść wygasłe klucze dostępu
        self.update_state(
            state='PROGRESS',
            meta={'current': 50, 'total': 100, 'status': 'Czyszczenie wygasłych kluczy...'}
        )
        
        from models import AccessKey
        expired_keys = AccessKey.query.filter(
            AccessKey.expires_at < datetime.now(),
            AccessKey.is_active
        ).all()
        
        for key in expired_keys:
            key.is_active = False
            cleaned_items['expired_access_keys'] += 1
        
        # Krok 3: Wyczyść stare logi
        self.update_state(
            state='PROGRESS',
            meta={'current': 75, 'total': 100, 'status': 'Czyszczenie starych logów...'}
        )
        
        logs_dir = Path("logs")
        if logs_dir.exists():
            cutoff_date = datetime.now() - timedelta(days=30)
            
            for log_file in logs_dir.glob("*.log.*"):
                try:
                    if log_file.stat().st_mtime < cutoff_date.timestamp():
                        log_file.unlink()
                        cleaned_items['old_logs'] += 1
                except Exception as e:
                    logger.warning(f"Error deleting old log file {log_file}: {e}")
        
        # Krok 4: Wyczyść pliki tymczasowe
        self.update_state(
            state='PROGRESS',
            meta={'current': 90, 'total': 100, 'status': 'Czyszczenie plików tymczasowych...'}
        )
        
        temp_dir = Path("/tmp")
        if temp_dir.exists():
            cutoff_date = datetime.now() - timedelta(hours=24)
            
            for temp_file in temp_dir.glob("mobywatel_*"):
                try:
                    if temp_file.stat().st_mtime < cutoff_date.timestamp():
                        temp_file.unlink()
                        cleaned_items['temp_files'] += 1
                except Exception as e:
                    logger.warning(f"Error deleting temp file {temp_file}: {e}")
        
        # Zatwierdź zmiany w bazie danych
        db.session.commit()
        
        # Krok 5: Zakończ
        self.update_state(
            state='SUCCESS',
            meta={'current': 100, 'total': 100, 'status': 'Czyszczenie zakończone'}
        )
        
        # Unieważnij cache
        cache_manager.invalidate_pattern("mobywatel:announcements:*")
        cache_manager.invalidate_pattern("mobywatel:access_keys:*")
        
        return {
            'success': True,
            'message': 'Czyszczenie zakończone pomyślnie',
            'cleaned_items': cleaned_items
        }
        
    except Exception as e:
        logger.error(f"Error in cleanup: {e}")
        db.session.rollback()
        self.update_state(
            state='FAILURE',
            meta={'error': str(e)}
        )
        return {
            'success': False,
            'error': str(e)
        }


@task_decorator('tasks.generate_backup')
def generate_backup(self, backup_type: str = 'full') -> Dict[str, Any]:
    """
    Asynchroniczne generowanie kopii zapasowej
    
    Args:
        backup_type: Typ kopii zapasowej ('full', 'users', 'files')
        
    Returns:
        Dict z wynikiem operacji
    """
    try:
        self.update_state(
            state='PROGRESS',
            meta={'current': 0, 'total': 100, 'status': 'Rozpoczynanie tworzenia kopii zapasowej...'}
        )
        
        import zipfile
        import tempfile
        
        # Utwórz tymczasowy katalog
        temp_dir = Path(tempfile.mkdtemp(prefix="mobywatel_backup_"))
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"mobywatel_backup_{backup_type}_{timestamp}.zip"
        backup_path = temp_dir / backup_filename
        
        self.update_state(
            state='PROGRESS',
            meta={'current': 20, 'total': 100, 'status': 'Przygotowanie struktury kopii zapasowej...'}
        )
        
        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            
            if backup_type in ['full', 'users']:
                # Krok 1: Kopia bazy danych
                self.update_state(
                    state='PROGRESS',
                    meta={'current': 40, 'total': 100, 'status': 'Kopiowanie bazy danych...'}
                )
                
                db_path = Path("auth_data/database.db")
                if db_path.exists():
                    zipf.write(db_path, "database.db")
            
            if backup_type in ['full', 'files']:
                # Krok 2: Kopia plików użytkowników
                self.update_state(
                    state='PROGRESS',
                    meta={'current': 60, 'total': 100, 'status': 'Kopiowanie plików użytkowników...'}
                )
                
                user_data_dir = Path("user_data")
                if user_data_dir.exists():
                    for user_folder in user_data_dir.iterdir():
                        if user_folder.is_dir():
                            for file_path in user_folder.rglob("*"):
                                if file_path.is_file():
                                    arcname = f"user_data/{file_path.relative_to(user_data_dir)}"
                                    zipf.write(file_path, arcname)
            
            if backup_type == 'full':
                # Krok 3: Kopia logów
                self.update_state(
                    state='PROGRESS',
                    meta={'current': 80, 'total': 100, 'status': 'Kopiowanie logów...'}
                )
                
                logs_dir = Path("logs")
                if logs_dir.exists():
                    for log_file in logs_dir.glob("*.log*"):
                        arcname = f"logs/{log_file.name}"
                        zipf.write(log_file, arcname)
        
        # Krok 4: Zakończ
        self.update_state(
            state='SUCCESS',
            meta={'current': 100, 'total': 100, 'status': 'Kopia zapasowa utworzona pomyślnie'}
        )
        
        return {
            'success': True,
            'message': 'Kopia zapasowa została utworzona pomyślnie',
            'backup_path': str(backup_path),
            'backup_size': backup_path.stat().st_size,
            'backup_type': backup_type
        }
        
    except Exception as e:
        logger.error(f"Error in backup generation: {e}")
        self.update_state(
            state='FAILURE',
            meta={'error': str(e)}
        )
        return {
            'success': False,
            'error': str(e)
        }


# Funkcje pomocnicze do zarządzania zadaniami
def get_task_status(task_id: str) -> Optional[Dict[str, Any]]:
    """Pobiera status zadania"""
    app = get_celery_app()
    if not CELERY_AVAILABLE or not app:
        return None
    
    try:
        task = app.AsyncResult(task_id)
        return {
            'task_id': task_id,
            'status': task.status,
            'result': task.result,
            'info': task.info
        }
    except Exception as e:
        logger.error(f"Error getting task status: {e}")
        return None


def cancel_task(task_id: str) -> bool:
    """Anuluje zadanie"""
    app = get_celery_app()
    if not CELERY_AVAILABLE or not app:
        return False
    
    try:
        app.control.revoke(task_id, terminate=True)
        return True
    except Exception as e:
        logger.error(f"Error canceling task: {e}")
        return False


def get_active_tasks() -> List[Dict[str, Any]]:
    """Pobiera listę aktywnych zadań"""
    app = get_celery_app()
    if not CELERY_AVAILABLE or not app:
        return []
    
    try:
        active_tasks = app.control.inspect().active()
        tasks = []
        
        if active_tasks:
            for worker, worker_tasks in (active_tasks.items() if hasattr(active_tasks, 'items') else []):
                if worker_tasks:
                    for task in worker_tasks:
                        tasks.append({
                            'task_id': task['id'],
                            'name': task['name'],
                            'worker': worker,
                            'start_time': task['time_start'],
                            'args': task['args'],
                            'kwargs': task['kwargs']
                        })
        
        return tasks
    except Exception as e:
        logger.error(f"Error getting active tasks: {e}")
        return []


# Funkcje do planowania zadań
def schedule_cleanup():
    """Planuje zadanie czyszczenia"""
    app = get_celery_app()
    if not CELERY_AVAILABLE or not app:
        return None
    
    try:
        # Wykonuj czyszczenie codziennie o 2:00
        if CELERY_AVAILABLE and app:
            # Użyj app.send_task jako alternatywy dla apply_async
            try:
                if hasattr(cleanup_expired_data, 'apply_async'):
                    cleanup_expired_data.apply_async(  # type: ignore[attr-defined]
                        countdown=60,  # Wykonaj za 1 minutę (dla testów)
                        # eta=datetime.now().replace(hour=2, minute=0, second=0, microsecond=0) + timedelta(days=1)
                    )
                else:
                    # Fallback using app.send_task
                    app.send_task('tasks.cleanup_expired_data', countdown=60)
            except AttributeError:
                # Fallback using app.send_task
                app.send_task('tasks.cleanup_expired_data', countdown=60)
        return True
    except Exception as e:
        logger.error(f"Error scheduling cleanup: {e}")
        return False


def schedule_backup(backup_type: str = 'full'):
    """Planuje zadanie tworzenia kopii zapasowej"""
    app = get_celery_app()
    if not CELERY_AVAILABLE or not app:
        return None
    
    try:
        if CELERY_AVAILABLE and app:
            # Użyj app.send_task jako alternatywy dla apply_async
            try:
                if hasattr(generate_backup, 'apply_async'):
                    task = generate_backup.apply_async(  # type: ignore[attr-defined]
                        args=[backup_type],
                        countdown=60  # Wykonaj za 1 minutę
                    )
                    return task.id
                else:
                    # Fallback using app.send_task
                    task = app.send_task('tasks.generate_backup', args=[backup_type], countdown=60)
                    return task.id
            except AttributeError:
                # Fallback using app.send_task
                task = app.send_task('tasks.generate_backup', args=[backup_type], countdown=60)
                return task.id
        return None
    except Exception as e:
        logger.error(f"Error scheduling backup: {e}")
        return None
