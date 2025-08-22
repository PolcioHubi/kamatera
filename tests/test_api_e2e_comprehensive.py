import pytest
import requests
import json
import time
from datetime import datetime, timedelta

class TestAPIE2EComprehensive:
    """Kompleksowe testy E2E dla API aplikacji."""
    
    @pytest.fixture(autouse=True)
    def setup(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'E2E-Test-Suite/1.0'
        })
    
    def test_api_rate_limiting_e2e(self):
        """Testuje rate limiting API."""
        # Próba wielokrotnego logowania
        for i in range(15):  # Powyżej limitu 10 req/s
            response = self.session.post(f"{self.base_url}/login", json={
                "username": "test_user",
                "password": "wrong_password"
            })
            
            if i >= 10:
                # Po przekroczeniu limitu powinien być błąd 429
                assert response.status_code == 429, f"Rate limiting nie działa: {response.status_code}"
                break
    
    def test_api_authentication_flow_e2e(self):
        """Testuje pełny flow uwierzytelniania API."""
        # 1. Rejestracja użytkownika
        reg_response = self.session.post(f"{self.base_url}/register", json={
            "username": f"api_user_{int(time.time())}",
            "password": "secure_password123",
            "accessKey": "test_access_key"
        })
        assert reg_response.status_code == 200
        reg_data = reg_response.json()
        assert reg_data["success"] is True
        
        # 2. Logowanie
        login_response = self.session.post(f"{self.base_url}/login", json={
            "username": reg_data["username"],
            "password": "secure_password123"
        })
        assert login_response.status_code == 200
        login_data = login_response.json()
        assert login_data["success"] is True
        
        # 3. Dostęp do chronionych endpointów
        profile_response = self.session.get(f"{self.base_url}/api/profile")
        assert profile_response.status_code == 200
        
        # 4. Wylogowanie
        logout_response = self.session.post(f"{self.base_url}/logout")
        assert logout_response.status_code == 200
        
        # 5. Próba dostępu po wylogowaniu
        profile_response = self.session.get(f"{self.base_url}/api/profile")
        assert profile_response.status_code == 401
    
    def test_api_data_validation_e2e(self):
        """Testuje walidację danych w API."""
        # Test nieprawidłowego PESEL
        response = self.session.post(f"{self.base_url}/api/validate-pesel", json={
            "pesel": "invalid_pesel"
        })
        assert response.status_code == 400
        data = response.json()
        assert "error" in data
        assert "PESEL" in data["error"]
        
        # Test nieprawidłowej daty
        response = self.session.post(f"{self.base_url}/api/validate-date", json={
            "date": "32.13.2024"
        })
        assert response.status_code == 400
        
        # Test nieprawidłowego emaila
        response = self.session.post(f"{self.base_url}/api/validate-email", json={
            "email": "invalid_email"
        })
        assert response.status_code == 400
    
    def test_api_file_operations_e2e(self):
        """Testuje operacje na plikach przez API."""
        # 1. Upload pliku
        files = {'file': ('test.txt', 'Test content', 'text/plain')}
        upload_response = self.session.post(f"{self.base_url}/api/upload", files=files)
        assert upload_response.status_code == 200
        
        upload_data = upload_response.json()
        file_id = upload_data["file_id"]
        
        # 2. Pobranie metadanych pliku
        meta_response = self.session.get(f"{self.base_url}/api/file/{file_id}/meta")
        assert meta_response.status_code == 200
        
        # 3. Pobranie pliku
        download_response = self.session.get(f"{self.base_url}/api/file/{file_id}/download")
        assert download_response.status_code == 200
        assert download_response.content == b'Test content'
        
        # 4. Usunięcie pliku
        delete_response = self.session.delete(f"{self.base_url}/api/file/{file_id}")
        assert delete_response.status_code == 200
    
    def test_api_error_handling_e2e(self):
        """Testuje obsługę błędów w API."""
        # Test nieistniejącego endpointu
        response = self.session.get(f"{self.base_url}/api/nonexistent")
        assert response.status_code == 404
        
        # Test nieprawidłowej metody HTTP
        response = self.session.post(f"{self.base_url}/api/profile")
        assert response.status_code == 405
        
        # Test nieprawidłowego JSON
        response = self.session.post(f"{self.base_url}/api/login", 
                                   data="invalid json",
                                   headers={'Content-Type': 'application/json'})
        assert response.status_code == 400
        
        # Test nieprawidłowego Content-Type
        response = self.session.post(f"{self.base_url}/api/login", 
                                   data="username=test&password=test",
                                   headers={'Content-Type': 'application/x-www-form-urlencoded'})
        assert response.status_code == 400
    
    def test_api_performance_e2e(self):
        """Testuje wydajność API."""
        # Test czasu odpowiedzi
        start_time = time.time()
        response = self.session.get(f"{self.base_url}/api/health")
        response_time = time.time() - start_time
        
        assert response.status_code == 200
        assert response_time < 1.0, f"API odpowiada za wolno: {response_time:.2f}s"
        
        # Test concurrent requests
        import concurrent.futures
        
        def make_request():
            return self.session.get(f"{self.base_url}/api/health")
        
        start_time = time.time()
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(10)]
            responses = [future.result() for future in futures]
        
        total_time = time.time() - start_time
        
        # Sprawdzenie czy wszystkie requesty się udały
        assert all(r.status_code == 200 for r in responses)
        assert total_time < 5.0, f"Concurrent requests trwają za długo: {total_time:.2f}s"
    
    def test_api_security_e2e(self):
        """Testuje bezpieczeństwo API."""
        # Test SQL Injection
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "'; SELECT * FROM users; --"
        ]
        
        for malicious_input in malicious_inputs:
            response = self.session.post(f"{self.base_url}/api/search", json={
                "query": malicious_input
            })
            # API powinno zwrócić błąd walidacji, nie błąd SQL
            assert response.status_code in [400, 422]
        
        # Test XSS
        xss_payload = "<script>alert('xss')</script>"
        response = self.session.post(f"{self.base_url}/api/comment", json={
            "text": xss_payload
        })
        
        if response.status_code == 200:
            # Sprawdzenie czy payload został zescaped
            data = response.json()
            assert "<script>" not in data["text"]
            assert "&lt;script&gt;" in data["text"] or "&lt;" in data["text"]
        
        # Test CSRF
        response = self.session.post(f"{self.base_url}/api/sensitive-action", json={
            "action": "delete_account"
        })
        # Powinien być błąd CSRF
        assert response.status_code in [400, 403]
    
    def test_api_data_integrity_e2e(self):
        """Testuje integralność danych w API."""
        # 1. Utworzenie danych
        test_data = {
            "name": "Test User",
            "email": "test@example.com",
            "age": 25
        }
        
        create_response = self.session.post(f"{self.base_url}/api/users", json=test_data)
        assert create_response.status_code == 201
        
        create_data = create_response.json()
        user_id = create_data["id"]
        
        # 2. Sprawdzenie czy dane zostały zapisane poprawnie
        get_response = self.session.get(f"{self.base_url}/api/users/{user_id}")
        assert get_response.status_code == 200
        
        retrieved_data = get_response.json()
        assert retrieved_data["name"] == test_data["name"]
        assert retrieved_data["email"] == test_data["email"]
        assert retrieved_data["age"] == test_data["age"]
        
        # 3. Aktualizacja danych
        updated_data = {"age": 26}
        update_response = self.session.patch(f"{self.base_url}/api/users/{user_id}", json=updated_data)
        assert update_response.status_code == 200
        
        # 4. Sprawdzenie czy aktualizacja się udała
        get_response = self.session.get(f"{self.base_url}/api/users/{user_id}")
        retrieved_data = get_response.json()
        assert retrieved_data["age"] == 26
        
        # 5. Usunięcie danych
        delete_response = self.session.delete(f"{self.base_url}/api/users/{user_id}")
        assert delete_response.status_code == 200
        
        # 6. Sprawdzenie czy dane zostały usunięte
        get_response = self.session.get(f"{self.base_url}/api/users/{user_id}")
        assert get_response.status_code == 404
    
    def test_api_logging_and_monitoring_e2e(self):
        """Testuje logowanie i monitoring API."""
        # Wykonanie kilku requestów
        endpoints = [
            "/api/health",
            "/api/status",
            "/api/version"
        ]
        
        for endpoint in endpoints:
            response = self.session.get(f"{self.base_url}{endpoint}")
            assert response.status_code in [200, 404]  # Niektóre mogą nie istnieć
        
        # Sprawdzenie logów (jeśli endpoint istnieje)
        logs_response = self.session.get(f"{self.base_url}/api/logs")
        if logs_response.status_code == 200:
            logs_data = logs_response.json()
            assert "logs" in logs_data
            assert len(logs_data["logs"]) > 0
        
        # Sprawdzenie metryk (jeśli endpoint istnieje)
        metrics_response = self.session.get(f"{self.base_url}/api/metrics")
        if metrics_response.status_code == 200:
            metrics_data = metrics_response.json()
            assert "request_count" in metrics_data
            assert "response_time_avg" in metrics_data
    
    def test_api_versioning_e2e(self):
        """Testuje versioning API."""
        # Test różnych wersji API
        versions = ["v1", "v2", "latest"]
        
        for version in versions:
            response = self.session.get(f"{self.base_url}/api/{version}/status")
            # Niektóre wersje mogą nie istnieć
            if response.status_code == 200:
                data = response.json()
                assert "version" in data
                assert "status" in data
    
    def test_api_documentation_e2e(self):
        """Testuje dokumentację API."""
        # Sprawdzenie Swagger/OpenAPI
        swagger_response = self.session.get(f"{self.base_url}/api/docs")
        if swagger_response.status_code == 200:
            assert "swagger" in swagger_response.text or "openapi" in swagger_response.text
        
        # Sprawdzenie endpointu z opisem
        response = self.session.get(f"{self.base_url}/api/")
        if response.status_code == 200:
            data = response.json()
            assert "endpoints" in data or "routes" in data
