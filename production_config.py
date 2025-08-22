"""
Konfiguracja produkcyjna dla aplikacji Dowodnowy HTML App
"""

import os


class ProductionConfig:
    # Bezpieczeństwo
    SECRET_KEY = os.environ.get("SECRET_KEY")
    
    # Validate critical environment variables
    @classmethod
    def validate_env_vars(cls):
        """Validate that all required environment variables are set."""
        required_vars = ['SECRET_KEY', 'ADMIN_USERNAME', 'ADMIN_PASSWORD']
        missing_vars = [var for var in required_vars if not os.environ.get(var)]
        if missing_vars:
            raise ValueError(f"Missing required environment variables: {missing_vars}")
        
        # Validate SECRET_KEY strength
        secret_key = os.environ.get("SECRET_KEY", "")
        if len(secret_key) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters long")
        
        return True

    # Flask settings
    DEBUG = False
    TESTING = False

    # Session settings
    SESSION_COOKIE_SECURE = True  # Tylko HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = 3600  # 1 godzina

    # Security headers
    SEND_FILE_MAX_AGE_DEFAULT = 31536000  # 1 rok dla plików statycznych

    # Upload settings
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB max upload

    # Logging
    LOG_LEVEL = "INFO"
    LOG_FILE = "logs/app.log"

    # Database (jeśli będzie używana w przyszłości)
    # DATABASE_URL = os.environ.get('DATABASE_URL')

    # Admin credentials (zmień w produkcji!)
    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME")
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

    # Rate limiting (wymaga Redis w produkcji dla wielu instancji)
    # Użyj "memory://" tylko dla pojedynczej instancji lub środowiska deweloperskiego.
    RATELIMIT_STORAGE_URL = os.environ.get(
        "RATELIMIT_STORAGE_URL", "redis://redis:6379"
    )

    @staticmethod
    def init_app(app):
        """Inicjalizacja konfiguracji dla aplikacji Flask"""
        # Validate environment variables before starting
        ProductionConfig.validate_env_vars()
        
        import logging
        from logging.handlers import RotatingFileHandler
        try:
            from pythonjsonlogger import jsonlogger  # type: ignore
            JsonFormatterBase = jsonlogger.JsonFormatter  # type: ignore
        except Exception:  # pragma: no cover
            import logging as _logging  # type: ignore
            class JsonFormatterBase(_logging.Formatter):  # type: ignore
                def format(self, record):
                    return f"{getattr(record, 'asctime', '')} {record.name} {record.levelname} {record.getMessage()} {record.pathname} {record.lineno}"

        if not app.debug and not app.testing:
            # Tworzenie katalogu logs jeśli nie istnieje
            if not os.path.exists("logs"):
                os.mkdir("logs")

            # Konfiguracja rotacji logów z formatowaniem JSON
            log_file = ProductionConfig.LOG_FILE
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=10240000,  # 10MB
                backupCount=10,
            )

            # Definicja formatu JSON
            formatter = JsonFormatterBase(
                "%(asctime)s %(name)s %(levelname)s %(message)s %(pathname)s %(lineno)d"
            )

            file_handler.setFormatter(formatter)
            app.logger.addHandler(file_handler)
            app.logger.setLevel(logging.INFO)
            app.logger.info(
                "Aplikacja Dowodnowy HTML uruchomiona w trybie produkcyjnym z logowaniem JSON."
            )
            # Avoid logging secret key in any environment


class DevelopmentConfig:
    """Konfiguracja deweloperska"""

    DEBUG = True
    SECRET_KEY = "dev-secret-key-change-in-production"
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB max upload for development
    
    # Security headers for development
    SEND_FILE_MAX_AGE_DEFAULT = 0  # No caching in development

    @staticmethod
    def init_app(app):
        pass


# Wybór konfiguracji na podstawie zmiennej środowiskowej
config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
