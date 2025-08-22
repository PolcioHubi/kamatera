"""
API Utilities - Ujednolicone funkcje do obsługi odpowiedzi API
"""
from datetime import datetime
from typing import Any, Dict, Optional

# Runtime imports with fallback
try:
    from flask import jsonify, Response  # type: ignore
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    jsonify = None
    Response = None


class APIResponse:
    """Klasa do ujednoliconego formatowania odpowiedzi API"""
    
    @staticmethod
    def success(
        data: Any = None, 
        message: str = "Operacja zakończona pomyślnie",
        status_code: int = 200,
        meta: Optional[Dict] = None
    ) -> Any:
        """
        Zwraca ujednoliconą odpowiedź sukcesu
        
        Args:
            data: Dane do zwrócenia
            message: Wiadomość sukcesu
            status_code: Kod statusu HTTP
            meta: Dodatkowe metadane (paginacja, etc.)
        """
        response = {
            "success": True,
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "status_code": status_code
        }
        
        if data is not None:
            response["data"] = data
            
        if meta:
            response["meta"] = meta
            
        if not FLASK_AVAILABLE or not jsonify:
            # Fallback gdy Flask nie jest dostępny
            return response, status_code
        return jsonify(response), status_code
    
    @staticmethod
    def error(
        message: str = "Wystąpił błąd",
        status_code: int = 400,
        error_code: Optional[str] = None,
        details: Optional[Dict] = None
    ) -> Any:
        """
        Zwraca ujednoliconą odpowiedź błędu
        
        Args:
            message: Wiadomość błędu
            status_code: Kod statusu HTTP
            error_code: Kod błędu dla frontendu
            details: Szczegóły błędu
        """
        response = {
            "success": False,
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "status_code": status_code
        }
        
        if error_code:
            response["error_code"] = error_code
            
        if details:
            response["details"] = details
            
        if not FLASK_AVAILABLE or not jsonify:
            # Fallback gdy Flask nie jest dostępny
            return response, status_code
        return jsonify(response), status_code
    
    @staticmethod
    def validation_error(
        errors: Dict[str, str],
        message: str = "Błędy walidacji"
    ) -> Any:
        """
        Zwraca odpowiedź błędu walidacji
        
        Args:
            errors: Słownik błędów walidacji {field: error_message}
            message: Ogólna wiadomość błędu
        """
        return APIResponse.error(
            message=message,
            status_code=422,
            error_code="VALIDATION_ERROR",
            details={"validation_errors": errors}
        )
    
    @staticmethod
    def not_found(
        resource: str = "Zasób",
        message: Optional[str] = None
    ) -> Any:
        """
        Zwraca odpowiedź 404 Not Found
        
        Args:
            resource: Nazwa zasobu, który nie został znaleziony
            message: Opcjonalna wiadomość
        """
        if not message:
            message = f"{resource} nie został znaleziony"
            
        return APIResponse.error(
            message=message,
            status_code=404,
            error_code="NOT_FOUND"
        )
    
    @staticmethod
    def unauthorized(
        message: str = "Brak uprawnień do wykonania tej operacji"
    ) -> Any:
        """
        Zwraca odpowiedź 401 Unauthorized
        """
        return APIResponse.error(
            message=message,
            status_code=401,
            error_code="UNAUTHORIZED"
        )
    
    @staticmethod
    def forbidden(
        message: str = "Dostęp zabroniony"
    ) -> Any:
        """
        Zwraca odpowiedź 403 Forbidden
        """
        return APIResponse.error(
            message=message,
            status_code=403,
            error_code="FORBIDDEN"
        )
    
    @staticmethod
    def server_error(
        message: str = "Wystąpił wewnętrzny błąd serwera",
        details: Optional[Dict] = None
    ) -> Any:
        """
        Zwraca odpowiedź 500 Internal Server Error
        """
        return APIResponse.error(
            message=message,
            status_code=500,
            error_code="INTERNAL_ERROR",
            details=details
        )


def api_response(
    success: bool = True,
    data: Any = None,
    message: str = "",
    status_code: int = 200,
    **kwargs
) -> Any:
    """
    Funkcja pomocnicza do szybkiego tworzenia odpowiedzi API
    (Zachowuje kompatybilność wsteczną)
    """
    if success:
        return APIResponse.success(data=data, message=message, status_code=status_code, **kwargs)
    else:
        return APIResponse.error(message=message, status_code=status_code, **kwargs)
