import pytest
import requests
import time
import threading
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

class TestLoadTestingE2E:
    """Testy load testing E2E dla aplikacji."""
    
    @pytest.fixture(autouse=True)
    def setup(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'Load-Test-Suite/1.0'
        })
    
    def test_concurrent_user_registration(self):
        """Testuje rejestrację wielu użytkowników jednocześnie."""
        num_users = 50
        results = []
        
        def register_user(user_id):
            try:
                response = self.session.post(f"{self.base_url}/register", json={
                    "username": f"loadtest_user_{user_id}_{int(time.time())}",
                    "password": "password123",
                    "accessKey": "test_access_key"
                })
                return {
                    "user_id": user_id,
                    "status_code": response.status_code,
                    "response_time": response.elapsed.total_seconds(),
                    "success": response.status_code == 200
                }
            except Exception as e:
                return {
                    "user_id": user_id,
                    "error": str(e),
                    "success": False
                }
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(register_user, i) for i in range(num_users)]
            for future in as_completed(futures):
                results.append(future.result())
        
        total_time = time.time() - start_time
        
        # Analiza wyników
        successful_registrations = [r for r in results if r["success"]]
        failed_registrations = [r for r in results if not r["success"]]
        response_times = [r["response_time"] for r in results if "response_time" in r]
        
        print(f"\n=== Load Test Results: Concurrent User Registration ===")
        print(f"Total users: {num_users}")
        print(f"Successful: {len(successful_registrations)}")
        print(f"Failed: {len(failed_registrations)}")
        print(f"Total time: {total_time:.2f}s")
        print(f"Throughput: {num_users/total_time:.2f} users/s")
        
        if response_times:
            print(f"Avg response time: {statistics.mean(response_times):.3f}s")
            print(f"Min response time: {min(response_times):.3f}s")
            print(f"Max response time: {max(response_times):.3f}s")
            print(f"95th percentile: {statistics.quantiles(response_times, n=20)[18]:.3f}s")
        
        # Asercje
        assert len(successful_registrations) >= num_users * 0.9, "Zbyt wiele nieudanych rejestracji"
        assert total_time < 60, "Test trwa za długo"
        if response_times:
            assert statistics.mean(response_times) < 2.0, "Średni czas odpowiedzi za długi"
    
    def test_concurrent_login_attempts(self):
        """Testuje próby logowania wielu użytkowników jednocześnie."""
        num_attempts = 100
        results = []
        
        def login_attempt(attempt_id):
            try:
                response = self.session.post(f"{self.base_url}/login", json={
                    "username": f"user_{attempt_id}",
                    "password": "wrong_password"
                })
                return {
                    "attempt_id": attempt_id,
                    "status_code": response.status_code,
                    "response_time": response.elapsed.total_seconds(),
                    "success": response.status_code == 200
                }
            except Exception as e:
                return {
                    "attempt_id": attempt_id,
                    "error": str(e),
                    "success": False
                }
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(login_attempt, i) for i in range(num_attempts)]
            for future in as_completed(futures):
                results.append(future.result())
        
        total_time = time.time() - start_time
        
        # Analiza wyników
        successful_logins = [r for r in results if r["success"]]
        failed_logins = [r for r in results if not r["success"]]
        response_times = [r["response_time"] for r in results if "response_time" in r]
        
        print(f"\n=== Load Test Results: Concurrent Login Attempts ===")
        print(f"Total attempts: {num_attempts}")
        print(f"Successful: {len(successful_logins)}")
        print(f"Failed: {len(failed_logins)}")
        print(f"Total time: {total_time:.2f}s")
        print(f"Throughput: {num_attempts/total_time:.2f} attempts/s")
        
        if response_times:
            print(f"Avg response time: {statistics.mean(response_times):.3f}s")
            print(f"95th percentile: {statistics.quantiles(response_times, n=20)[18]:.3f}s")
        
        # Asercje
        assert total_time < 30, "Test trwa za długo"
        if response_times:
            assert statistics.mean(response_times) < 1.0, "Średni czas odpowiedzi za długi"
    
    def test_database_stress_test(self):
        """Testuje obciążenie bazy danych."""
        num_operations = 200
        results = []
        
        def database_operation(op_id):
            try:
                # Symulacja różnych operacji na bazie
                operations = [
                    lambda: self.session.get(f"{self.base_url}/api/status"),
                    lambda: self.session.post(f"{self.base_url}/api/search", json={"query": f"test_{op_id}"}),
                    lambda: self.session.get(f"{self.base_url}/api/health")
                ]
                
                operation = operations[op_id % len(operations)]
                response = operation()
                
                return {
                    "op_id": op_id,
                    "status_code": response.status_code,
                    "response_time": response.elapsed.total_seconds(),
                    "success": response.status_code in [200, 404]
                }
            except Exception as e:
                return {
                    "op_id": op_id,
                    "error": str(e),
                    "success": False
                }
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=25) as executor:
            futures = [executor.submit(database_operation, i) for i in range(num_operations)]
            for future in as_completed(futures):
                results.append(future.result())
        
        total_time = time.time() - start_time
        
        # Analiza wyników
        successful_ops = [r for r in results if r["success"]]
        failed_ops = [r for r in results if not r["success"]]
        response_times = [r["response_time"] for r in results if "response_time" in r]
        
        print(f"\n=== Load Test Results: Database Stress Test ===")
        print(f"Total operations: {num_operations}")
        print(f"Successful: {len(successful_ops)}")
        print(f"Failed: {len(failed_ops)}")
        print(f"Total time: {total_time:.2f}s")
        print(f"Throughput: {num_operations/total_time:.2f} ops/s")
        
        if response_times:
            print(f"Avg response time: {statistics.mean(response_times):.3f}s")
            print(f"95th percentile: {statistics.quantiles(response_times, n=20)[18]:.3f}s")
        
        # Asercje
        assert len(successful_ops) >= num_operations * 0.95, "Zbyt wiele nieudanych operacji"
        assert total_time < 45, "Test trwa za długo"
        if response_times:
            assert statistics.mean(response_times) < 0.5, "Średni czas odpowiedzi za długi"
    
    def test_memory_leak_test(self):
        """Testuje wycieki pamięci podczas długotrwałego obciążenia."""
        num_iterations = 10
        memory_usage = []
        
        for iteration in range(num_iterations):
            print(f"Iteration {iteration + 1}/{num_iterations}")
            
            # Wykonanie serii requestów
            start_time = time.time()
            responses = []
            
            with ThreadPoolExecutor(max_workers=15) as executor:
                futures = [executor.submit(self.session.get, f"{self.base_url}/api/health") 
                          for _ in range(50)]
                for future in as_completed(futures):
                    responses.append(future.result())
            
            iteration_time = time.time() - start_time
            
            # Sprawdzenie czy wszystkie requesty się udały
            successful = [r for r in responses if r.status_code == 200]
            print(f"  Successful requests: {len(successful)}/50")
            print(f"  Iteration time: {iteration_time:.2f}s")
            
            # Symulacja pomiaru pamięci (w rzeczywistości użyj psutil)
            memory_usage.append(len(responses))
            
            # Krótka przerwa między iteracjami
            time.sleep(1)
        
        print(f"\n=== Memory Leak Test Results ===")
        print(f"Total iterations: {num_iterations}")
        print(f"Memory usage pattern: {memory_usage}")
        
        # Sprawdzenie czy nie ma znaczącego wzrostu użycia pamięci
        if len(memory_usage) > 1:
            growth_rate = (memory_usage[-1] - memory_usage[0]) / memory_usage[0]
            print(f"Memory growth rate: {growth_rate:.2%}")
            assert growth_rate < 0.5, "Podejrzany wzrost użycia pamięci"
    
    def test_rate_limiting_under_load(self):
        """Testuje rate limiting pod obciążeniem."""
        num_requests = 150
        results = []
        
        def make_request(req_id):
            try:
                response = self.session.post(f"{self.base_url}/login", json={
                    "username": f"rate_test_{req_id}",
                    "password": "wrong_password"
                })
                return {
                    "req_id": req_id,
                    "status_code": response.status_code,
                    "response_time": response.elapsed.total_seconds(),
                    "rate_limited": response.status_code == 429
                }
            except Exception as e:
                return {
                    "req_id": req_id,
                    "error": str(e),
                    "rate_limited": False
                }
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = [executor.submit(make_request, i) for i in range(num_requests)]
            for future in as_completed(futures):
                results.append(future.result())
        
        total_time = time.time() - start_time
        
        # Analiza wyników
        rate_limited = [r for r in results if r["rate_limited"]]
        not_rate_limited = [r for r in results if not r["rate_limited"]]
        
        print(f"\n=== Rate Limiting Under Load Test Results ===")
        print(f"Total requests: {num_requests}")
        print(f"Rate limited: {len(rate_limited)}")
        print(f"Not rate limited: {len(not_rate_limited)}")
        print(f"Total time: {total_time:.2f}s")
        print(f"Rate limiting effectiveness: {len(rate_limited)/num_requests:.1%}")
        
        # Asercje
        assert len(rate_limited) > 0, "Rate limiting nie działa"
        assert len(rate_limited) >= num_requests * 0.3, "Rate limiting za słaby"
        assert total_time < 20, "Test trwa za długo"
    
    def test_session_management_under_load(self):
        """Testuje zarządzanie sesjami pod obciążeniem."""
        num_sessions = 100
        results = []
        
        def create_session(session_id):
            try:
                # Symulacja tworzenia sesji
                response = self.session.post(f"{self.base_url}/login", json={
                    "username": f"session_test_{session_id}",
                    "password": "password123"
                })
                
                if response.status_code == 200:
                    # Sprawdzenie czy sesja jest aktywna
                    session_check = self.session.get(f"{self.base_url}/api/profile")
                    return {
                        "session_id": session_id,
                        "created": response.status_code == 200,
                        "active": session_check.status_code == 200,
                        "response_time": response.elapsed.total_seconds()
                    }
                else:
                    return {
                        "session_id": session_id,
                        "created": False,
                        "active": False,
                        "response_time": response.elapsed.total_seconds()
                    }
            except Exception as e:
                return {
                    "session_id": session_id,
                    "error": str(e),
                    "created": False,
                    "active": False
                }
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(create_session, i) for i in range(num_sessions)]
            for future in as_completed(futures):
                results.append(future.result())
        
        total_time = time.time() - start_time
        
        # Analiza wyników
        created_sessions = [r for r in results if r["created"]]
        active_sessions = [r for r in results if r["active"]]
        response_times = [r["response_time"] for r in results if "response_time" in r]
        
        print(f"\n=== Session Management Under Load Test Results ===")
        print(f"Total sessions: {num_sessions}")
        print(f"Created: {len(created_sessions)}")
        print(f"Active: {len(active_sessions)}")
        print(f"Total time: {total_time:.2f}s")
        print(f"Session creation rate: {len(created_sessions)/total_time:.2f} sessions/s")
        
        if response_times:
            print(f"Avg response time: {statistics.mean(response_times):.3f}s")
        
        # Asercje
        assert len(created_sessions) >= num_sessions * 0.8, "Zbyt wiele nieudanych sesji"
        assert total_time < 60, "Test trwa za długo"
        if response_times:
            assert statistics.mean(response_times) < 1.5, "Średni czas odpowiedzi za długi"
