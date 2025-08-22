# API Examples - Enhanced Mobywatel Creator

## 🔄 **UJEDNOLICONE API RESPONSES**

Wszystkie endpointy API v2 zwracają ujednoliconą strukturę odpowiedzi:

### ✅ **Sukces**
```json
{
  "success": true,
  "message": "Operacja zakończona pomyślnie",
  "timestamp": "2024-01-15T10:30:00.123456",
  "status_code": 200,
  "data": {
    // Dane odpowiedzi
  }
}
```

### ❌ **Błąd**
```json
{
  "success": false,
  "message": "Wystąpił błąd",
  "timestamp": "2024-01-15T10:30:00.123456",
  "status_code": 400,
  "error_code": "VALIDATION_ERROR",
  "details": {
    // Szczegóły błędu
  }
}
```

---

## 🔐 **ENHANCED AUTHENTICATION API**

### POST `/api/v2/login`
```bash
curl -X POST http://localhost:5000/api/v2/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "SecurePass123!",
    "remember": true
  }'
```

**Odpowiedź:**
```json
{
  "success": true,
  "message": "Logowanie zakończone pomyślnie",
  "timestamp": "2024-01-15T10:30:00.123456",
  "status_code": 200,
  "data": {
    "username": "testuser",
    "created_at": "2024-01-01T00:00:00",
    "last_login": "2024-01-15T10:30:00",
    "is_active": true,
    "hubert_coins": 100
  }
}
```

### POST `/api/v2/register`
```bash
curl -X POST http://localhost:5000/api/v2/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser",
    "password": "SecurePass123!",
    "confirm_password": "SecurePass123!",
    "access_key": "VALID_ACCESS_KEY_123",
    "referral_code": "REF123"
  }'
```

---

## 👤 **USER PROFILE API**

### GET `/api/v2/user/profile`
```bash
curl -X GET http://localhost:5000/api/v2/user/profile \
  -H "Authorization: Bearer YOUR_SESSION_TOKEN"
```

**Odpowiedź:**
```json
{
  "success": true,
  "message": "Operacja zakończona pomyślnie",
  "timestamp": "2024-01-15T10:30:00.123456",
  "status_code": 200,
  "data": {
    "username": "testuser",
    "created_at": "2024-01-01T00:00:00",
    "last_login": "2024-01-15T10:30:00",
    "is_active": true,
    "hubert_coins": 100,
    "has_seen_tutorial": false
  }
}
```

---

## 📢 **ANNOUNCEMENTS API**

### GET `/api/v2/announcements`
```bash
curl -X GET http://localhost:5000/api/v2/announcements
```

**Odpowiedź:**
```json
{
  "success": true,
  "message": "Operacja zakończona pomyślnie",
  "timestamp": "2024-01-15T10:30:00.123456",
  "status_code": 200,
  "data": [
    {
      "id": 1,
      "title": "Ważne ogłoszenie",
      "message": "Treść ogłoszenia",
      "type": "info",
      "created_at": "2024-01-15T10:00:00"
    }
  ]
}
```

---

## 📊 **STATISTICS API**

### GET `/api/v2/stats`
```bash
curl -X GET http://localhost:5000/api/v2/stats \
  -H "Authorization: Bearer YOUR_SESSION_TOKEN"
```

**Odpowiedź:**
```json
{
  "success": true,
  "message": "Operacja zakończona pomyślnie",
  "timestamp": "2024-01-15T10:30:00.123456",
  "status_code": 200,
  "data": {
    "total_users": 150,
    "total_files": 1250,
    "total_size": 1048576000,
    "active_users_today": 45
  }
}
```

---

## 🔄 **ASYNC TASKS API**

### GET `/api/v2/tasks/{task_id}/status`
```bash
curl -X GET http://localhost:5000/api/v2/tasks/abc123/status \
  -H "Authorization: Bearer YOUR_SESSION_TOKEN"
```

**Odpowiedź:**
```json
{
  "success": true,
  "message": "Operacja zakończona pomyślnie",
  "timestamp": "2024-01-15T10:30:00.123456",
  "status_code": 200,
  "data": {
    "task_id": "abc123",
    "status": "PROGRESS",
    "result": null,
    "info": {
      "current": 50,
      "total": 100,
      "status": "Przetwarzanie pliku..."
    }
  }
}
```

---

## 🗄️ **ADMIN API**

### GET `/api/v2/database/stats`
```bash
curl -X GET http://localhost:5000/api/v2/database/stats \
  -H "Authorization: Bearer ADMIN_SESSION_TOKEN"
```

**Odpowiedź:**
```json
{
  "success": true,
  "message": "Operacja zakończona pomyślnie",
  "timestamp": "2024-01-15T10:30:00.123456",
  "status_code": 200,
  "data": {
    "tables": {
      "users": {
        "count": 150,
        "size_bytes": 1048576
      },
      "files": {
        "count": 1250,
        "size_bytes": 5242880
      }
    },
    "indexes": [
      {
        "name": "idx_user_username",
        "type": "index"
      }
    ],
    "cache_stats": {
      "cache_hits": 1000,
      "cache_misses": 100
    }
  }
}
```

### GET `/api/v2/cache/stats`
```bash
curl -X GET http://localhost:5000/api/v2/cache/stats \
  -H "Authorization: Bearer ADMIN_SESSION_TOKEN"
```

**Odpowiedź:**
```json
{
  "success": true,
  "message": "Operacja zakończona pomyślnie",
  "timestamp": "2024-01-15T10:30:00.123456",
  "status_code": 200,
  "data": {
    "hits": 1000,
    "misses": 100,
    "sets": 500,
    "deletes": 50,
    "hit_rate": 90.91,
    "memory_cache_size": 25,
    "redis_available": true
  }
}
```

### POST `/api/v2/cache/clear`
```bash
curl -X POST http://localhost:5000/api/v2/cache/clear \
  -H "Authorization: Bearer ADMIN_SESSION_TOKEN"
```

---

## 🔧 **WALIDACJA DANYCH**

Wszystkie endpointy używają Marshmallow schemas do walidacji:

### Przykład błędu walidacji:
```json
{
  "success": false,
  "message": "Błędy walidacji",
  "timestamp": "2024-01-15T10:30:00.123456",
  "status_code": 422,
  "error_code": "VALIDATION_ERROR",
  "details": {
    "validation_errors": {
      "username": "Nazwa użytkownika musi mieć od 3 do 50 znaków",
      "password": "Hasło musi zawierać wielkie litery, małe litery, cyfry i znaki specjalne"
    }
  }
}
```

---

## 🚀 **CACHING**

Wszystkie endpointy automatycznie cache'ują odpowiedzi:

- **User profile**: 5 minut
- **Announcements**: 5 minut  
- **Statistics**: 1 minuta
- **Login attempts**: 15 minut (rate limiting)

---

## 📝 **KOMENDY CLI**

### Optymalizacja bazy danych:
```bash
flask optimize-db
```

### Planowanie zadań:
```bash
flask schedule-cleanup
```

---

## 🔄 **ASYNC OPERATIONS**

### Generowanie dokumentu:
```python
from async_tasks import process_document_generation

# Uruchom zadanie asynchroniczne
task = process_document_generation.delay(user_data)

# Sprawdź status
status = task.status  # PENDING, PROGRESS, SUCCESS, FAILURE
result = task.result  # Wynik po zakończeniu
```

### Przetwarzanie pliku:
```python
from async_tasks import process_file_upload

task = process_file_upload.delay({
    'username': 'testuser',
    'filename': 'document.pdf',
    'content': file_content
})
```

---

## 🐳 **DOCKER COMPOSE**

Uruchomienie z Redis i Celery:

```bash
# Uruchom wszystkie serwisy
docker-compose up -d

# Sprawdź status
docker-compose ps

# Logi aplikacji
docker-compose logs app

# Logi Celery worker
docker-compose logs celery-worker

# Logi Redis
docker-compose logs redis
```

---

## 📊 **MONITORING**

### Statystyki cache:
```bash
curl http://localhost:5000/api/v2/cache/stats
```

### Statystyki bazy danych:
```bash
curl http://localhost:5000/api/v2/database/stats
```

### Status zadań:
```bash
curl http://localhost:5000/api/v2/tasks/{task_id}/status
```
