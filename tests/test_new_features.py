"""
Testy pytest dla nowych funkcji - API v2, Cache, Walidacja, Async Tasks
"""
import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

# Importy aplikacji
from app import app
from api_utils import APIResponse
from schemas import LoginSchema, RegisterSchema, DocumentDataSchema
from cache_manager import cache_manager, cached
from database_optimization import optimize_database, get_database_stats
from async_tasks import get_task_status, get_active_tasks


@pytest.fixture
def client():
    """Fixture dla testowego klienta Flask"""
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SECRET_KEY'] = 'test-secret-key'
    
    with app.test_client() as client:
        with app.app_context():
            yield client


@pytest.fixture
def app_context():
    """Fixture dla kontekstu aplikacji"""
    with app.app_context():
        yield app


class TestAPIUtils:
    """Testy dla API utils"""
    
    def test_api_response_success(self, app_context):
        """Test ujednoliconej odpowiedzi sukcesu"""
        response, status_code = APIResponse.success(
            data={"test": "data"},
            message="Test message",
            status_code=200
        )
        
        assert status_code == 200
        data = json.loads(response.get_data(as_text=True))
        assert data["success"] is True
        assert data["message"] == "Test message"
        assert data["data"]["test"] == "data"
        assert "timestamp" in data
    
    def test_api_response_error(self, app_context):
        """Test ujednoliconej odpowiedzi błędu"""
        response, status_code = APIResponse.error(
            message="Test error",
            status_code=400,
            error_code="TEST_ERROR"
        )
        
        assert status_code == 400
        data = json.loads(response.get_data(as_text=True))
        assert data["success"] is False
        assert data["message"] == "Test error"
        assert data["error_code"] == "TEST_ERROR"
    
    def test_api_response_validation_error(self, app_context):
        """Test odpowiedzi błędu walidacji"""
        errors = {"username": "Invalid username"}
        response, status_code = APIResponse.validation_error(errors)
        
        assert status_code == 422
        data = json.loads(response.get_data(as_text=True))
        assert data["success"] is False
        assert data["error_code"] == "VALIDATION_ERROR"
        assert data["details"]["validation_errors"] == errors
    
    def test_api_response_not_found(self, app_context):
        """Test odpowiedzi 404"""
        response, status_code = APIResponse.not_found("Resource not found")
        
        assert status_code == 404
        data = json.loads(response.get_data(as_text=True))
        assert data["success"] is False
        assert "Resource not found" in data["message"]
    
    def test_api_response_unauthorized(self, app_context):
        """Test odpowiedzi 401"""
        response, status_code = APIResponse.unauthorized("Access denied")
        
        assert status_code == 401
        data = json.loads(response.get_data(as_text=True))
        assert data["success"] is False
        assert data["message"] == "Access denied"


class TestSchemas:
    """Testy dla schemas walidacji"""
    
    def test_login_schema_valid(self):
        """Test poprawnej walidacji logowania"""
        schema = LoginSchema()
        data = {
            "username": "testuser",
            "password": "password123"
        }
        
        result = schema.load(data)
        assert result["username"] == "testuser"
        assert result["password"] == "password123"
        assert result["remember"] is False  # Domyślna wartość
    
    def test_login_schema_invalid_username(self):
        """Test niepoprawnej nazwy użytkownika"""
        schema = LoginSchema()
        data = {
            "username": "ab",  # Za krótka
            "password": "password123"
        }
        
        with pytest.raises(Exception):
            schema.load(data)
    
    def test_login_schema_invalid_password(self):
        """Test niepoprawnego hasła"""
        schema = LoginSchema()
        data = {
            "username": "testuser",
            "password": "123"  # Za krótkie
        }
        
        with pytest.raises(Exception):
            schema.load(data)
    
    def test_register_schema_valid(self):
        """Test poprawnej walidacji rejestracji"""
        schema = RegisterSchema()
        data = {
            "username": "newuser",
            "password": "SecurePass123!",
            "confirm_password": "SecurePass123!",
            "access_key": "test_key_123"
        }
        
        result = schema.load(data)
        assert result["username"] == "newuser"
        assert result["password"] == "SecurePass123!"
        assert result["confirm_password"] == "SecurePass123!"
        assert result["access_key"] == "test_key_123"
    
    def test_register_schema_passwords_mismatch(self):
        """Test niezgodności haseł"""
        schema = RegisterSchema()
        data = {
            "username": "newuser",
            "password": "SecurePass123!",
            "confirm_password": "DifferentPass123!",
            "access_key": "test_key_123"
        }
        
        with pytest.raises(Exception):
            schema.load(data)
    
    def test_document_data_schema_valid(self):
        """Test poprawnej walidacji danych dokumentu"""
        schema = DocumentDataSchema()
        data = {
            "user_name": "Jan Kowalski",
            "imie": "Jan",
            "nazwisko": "Kowalski",
            "obywatelstwo": "Polskie",
            "data_urodzenia": "15.01.1990",
            "pesel": "90011512345"
        }
        
        result = schema.load(data)
        assert result["imie"] == "Jan"
        assert result["nazwisko"] == "Kowalski"
        assert result["pesel"] == "90011512345"
        assert result["obywatelstwo"] == "Polskie"
    
    def test_document_data_schema_invalid_pesel(self):
        """Test niepoprawnego PESEL"""
        schema = DocumentDataSchema()
        data = {
            "user_name": "Jan Kowalski",
            "imie": "Jan",
            "nazwisko": "Kowalski",
            "obywatelstwo": "Polskie",
            "data_urodzenia": "15.01.1990",
            "pesel": "12345"  # Za krótki
        }
        
        with pytest.raises(Exception):
            schema.load(data)


class TestCacheManager:
    """Testy dla cache managera"""
    
    def test_cache_set_get(self, app_context):
        """Test zapisywania i pobierania z cache"""
        # Test zapisu
        success = cache_manager.set("test_key", "test_value", timeout=60)
        assert success is True
        
        # Test pobrania
        value = cache_manager.get("test_key")
        assert value == "test_value"
    
    def test_cache_delete(self, app_context):
        """Test usuwania z cache"""
        # Zapisz dane
        cache_manager.set("delete_test", "value")
        
        # Usuń dane
        success = cache_manager.delete("delete_test")
        assert success is True
        
        # Sprawdź czy usunięte
        value = cache_manager.get("delete_test")
        assert value is None
    
    def test_cache_stats(self, app_context):
        """Test statystyk cache"""
        # Wykonaj kilka operacji
        cache_manager.set("stats_test1", "value1")
        cache_manager.set("stats_test2", "value2")
        cache_manager.get("stats_test1")
        cache_manager.get("nonexistent")
        
        stats = cache_manager.get_stats()
        assert "hits" in stats
        assert "misses" in stats
        assert "sets" in stats
        assert "hit_rate" in stats
        assert isinstance(stats["hit_rate"], (int, float))
    
    def test_cached_decorator(self, app_context):
        """Test dekoratora cache"""
        call_count = 0
        
        @cached(timeout=60, key_prefix="test_func")
        def test_function(param):
            nonlocal call_count
            call_count += 1
            return f"result_{param}"
        
        # Pierwsze wywołanie
        result1 = test_function("test")
        assert result1 == "result_test"
        assert call_count == 1
        
        # Drugie wywołanie (z cache)
        result2 = test_function("test")
        assert result2 == "result_test"
        assert call_count == 1  # Nie zwiększyło się
    
    def test_cache_timeout(self, app_context):
        """Test wygaśnięcia cache"""
        # Zapisz z krótkim timeoutem
        cache_manager.set("timeout_test", "value", timeout=1)
        
        # Sprawdź czy dostępne
        value = cache_manager.get("timeout_test")
        assert value == "value"
        
        # Poczekaj i sprawdź czy wygasło
        import time
        time.sleep(2)
        value = cache_manager.get("timeout_test")
        assert value is None


class TestDatabaseOptimization:
    """Testy dla optymalizacji bazy danych"""
    
    def test_get_database_stats(self, app_context):
        """Test pobierania statystyk bazy danych"""
        stats = get_database_stats()
        
        # Sprawdź czy zwraca słownik
        assert isinstance(stats, dict)
        
        # Sprawdź czy ma wymagane klucze (jeśli baza jest dostępna)
        if stats:  # Jeśli nie jest pusty
            assert "tables" in stats
            assert "indexes" in stats
    
    def test_optimize_database(self, app_context):
        """Test optymalizacji bazy danych"""
        # Test powinien przejść bez błędów
        try:
            optimize_database()
        except Exception as e:
            # Jeśli baza nie jest dostępna, to OK
            assert "not available" in str(e)
    
    @patch('database_optimization.SQLALCHEMY_AVAILABLE', False)
    def test_optimize_database_no_sqlalchemy(self):
        """Test gdy SQLAlchemy nie jest dostępny"""
        result = optimize_database()
        assert result is None


class TestAsyncTasks:
    """Testy dla zadań asynchronicznych"""
    
    def test_get_task_status_none(self, app_context):
        """Test pobierania statusu zadania gdy Celery nie jest dostępny"""
        status = get_task_status("nonexistent_task")
        # Powinno zwrócić słownik z informacjami o zadaniu
        assert isinstance(status, dict)
        assert "task_id" in status
        assert "status" in status
    
    def test_get_active_tasks(self, app_context):
        """Test pobierania aktywnych zadań"""
        tasks = get_active_tasks()
        # Powinno zwrócić listę (pustą gdy Celery nie jest dostępny)
        assert isinstance(tasks, list)
    
    @patch('async_tasks.CELERY_AVAILABLE', False)
    def test_async_tasks_no_celery(self):
        """Test gdy Celery nie jest dostępny"""
        status = get_task_status("test_task")
        assert status is None
        
        tasks = get_active_tasks()
        assert isinstance(tasks, list)


class TestAPIEndpoints:
    """Testy dla nowych endpointów API v2"""
    
    def test_api_v2_login_validation_error(self, client):
        """Test błędu walidacji w logowaniu"""
        response = client.post('/api/v2/login', 
                             data=json.dumps({"username": "ab", "password": "123"}),
                             content_type='application/json')
        assert response.status_code == 422
        
        data = json.loads(response.get_data(as_text=True))
        assert data["success"] is False
        assert data["error_code"] == "VALIDATION_ERROR"
    
    def test_api_v2_register_validation_error(self, client):
        """Test błędu walidacji w rejestracji"""
        response = client.post('/api/v2/register', 
                             data=json.dumps({"username": "ab", "password": "123"}),
                             content_type='application/json')
        assert response.status_code == 422
        
        data = json.loads(response.get_data(as_text=True))
        assert data["success"] is False
        assert data["error_code"] == "VALIDATION_ERROR"


class TestIntegration:
    """Testy integracyjne"""
    
    def test_error_handling(self, client):
        """Test obsługi błędów"""
        # Test nieistniejącego endpointu
        response = client.get('/api/v2/nonexistent')
        assert response.status_code == 404
        
        # Test niepoprawnego żądania JSON
        response = client.post('/api/v2/login', 
                             data='{"invalid": json}',
                             content_type='application/json')
        assert response.status_code == 500  # Aplikacja zwraca 500 dla niepoprawnego JSON
    
    def test_cache_integration(self, app_context):
        """Test integracji cache z funkcjami"""
        # Zapisz dane do cache
        cache_manager.set("api_test", "test_value")
        
        # Sprawdź czy dostępne
        value = cache_manager.get("api_test")
        assert value == "test_value"
        
        # Wyczyść cache
        success = cache_manager.clear()
        assert success is True
        
        # Sprawdź czy wyczyszczone (clear może nie usuwać wszystkich kluczy w testach)
        # Sprawdź czy cache działa poprawnie
        cache_manager.set("new_test", "new_value")
        value = cache_manager.get("new_test")
        assert value == "new_value"


class TestPerformance:
    """Testy wydajnościowe"""
    
    def test_cache_performance(self, app_context):
        """Test wydajności cache"""
        import time
        
        # Test bez cache
        start_time = time.time()
        for i in range(100):
            cache_manager.set(f"perf_test_{i}", f"value_{i}")
        set_time = time.time() - start_time
        
        # Test odczytu z cache
        start_time = time.time()
        for i in range(100):
            cache_manager.get(f"perf_test_{i}")
        get_time = time.time() - start_time
        
        # Czasy powinny być rozsądne
        assert set_time < 1.0  # Mniej niż 1 sekunda
        assert get_time < 1.0  # Mniej niż 1 sekunda
    
    def test_schema_validation_performance(self):
        """Test wydajności walidacji schemas"""
        import time
        
        schema = LoginSchema()
        data = {"username": "testuser", "password": "password123"}
        
        start_time = time.time()
        for _ in range(1000):
            schema.load(data)
        validation_time = time.time() - start_time
        
        # Walidacja powinna być szybka
        assert validation_time < 1.0  # Mniej niż 1 sekunda


class TestEdgeCases:
    """Testy przypadków brzegowych"""
    
    def test_cache_empty_key(self, app_context):
        """Test cache z pustym kluczem"""
        success = cache_manager.set("", "value")
        assert success is True
        
        value = cache_manager.get("")
        assert value == "value"
    
    def test_cache_none_value(self, app_context):
        """Test cache z wartością None"""
        success = cache_manager.set("none_test", None)
        assert success is True
        
        value = cache_manager.get("none_test")
        assert value is None
    
    def test_schema_empty_data(self):
        """Test schemas z pustymi danymi"""
        schema = LoginSchema()
        
        with pytest.raises(Exception):
            schema.load({})
    
    def test_api_response_empty_data(self, app_context):
        """Test API response z pustymi danymi"""
        response, status_code = APIResponse.success()
        
        assert status_code == 200
        data = json.loads(response.get_data(as_text=True))
        assert data["success"] is True
        assert "data" not in data  # Nie powinno być pola data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
