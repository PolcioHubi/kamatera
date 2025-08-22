#!/bin/bash

# ==============================================================================
# Skrypt do pełnego wdrożenia aplikacji Flask/Gunicorn z Nginx, SSL i Logowaniem
# WERSJA ENHANCED v4.0 (2025-01-15)
# Zaktualizowany dla Enhanced Mobywatel Creator v2.0.0
# Wspiera: API v2, Cache (Redis), Async Tasks (Celery), Schemas Walidacji
# ==============================================================================

# Zatrzymaj skrypt w przypadku błędu
set -e

# --- ZMIENNE KONFIGURACYJNE ---
SERVICE_NAME="mobywatel"
PROJECT_USER="mobywatel_user"
DEST_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
DOMAIN="185-139-230-222.cloud-xip.com"
SSL_EMAIL="polciovps@atomicmail.io"
GUNICORN_WORKERS=$((2 * $(nproc) + 1))

echo ">>> START: Rozpoczynanie wdrożenia Enhanced Mobywatel Creator v2.0.0..."

# --- KROK 0: Sprawdzanie i tworzenie użytkownika systemowego ---
echo ">>> KROK 0: Sprawdzanie i tworzenie użytkownika systemowego $PROJECT_USER..."
if ! id "$PROJECT_USER" &>/dev/null; then
    sudo useradd -r -s /bin/false $PROJECT_USER
    echo "Użytkownik $PROJECT_USER został utworzony."
else
    echo "Użytkownik $PROJECT_USER już istnieje."
fi

# --- KROK 1: Instalowanie zależności systemowych ---
echo ">>> KROK 1: Instalowanie Nginx, Pip, Venv, Certbota, Redis i Celery..."
sudo apt-get update
sudo apt-get install -y nginx python3-pip python3-venv certbot python3-certbot-nginx redis-server supervisor

# Upewnianie się, że Redis jest uruchomiony i włączony
echo ">>> Upewnianie się, że Redis jest uruchomiony i włączony..."
sudo systemctl start redis-server
sudo systemctl enable redis-server

# --- KROK 1.5: Dodawanie użytkownika www-data do grupy ---
echo ">>> KROK 1.5: Dodawanie użytkownika www-data do grupy $PROJECT_USER..."
sudo usermod -aG $PROJECT_USER www-data

# --- KROK 2: Przygotowanie katalogu aplikacji ---
echo ">>> KROK 2: Przygotowanie katalogu aplikacji..."
sudo chown -R $PROJECT_USER:$PROJECT_USER $DEST_DIR
sudo mkdir -p $DEST_DIR/logs
sudo mkdir -p $DEST_DIR/celery_logs
sudo chown -R $PROJECT_USER:$PROJECT_USER $DEST_DIR/logs
sudo chown -R $PROJECT_USER:$PROJECT_USER $DEST_DIR/celery_logs
sudo find $DEST_DIR -type d -exec chmod 750 {} \;
sudo find $DEST_DIR -type f -exec chmod 640 {} \;
sudo chmod +x $0

# --- KROK 3: Konfiguracja środowiska Python ---
echo ">>> KROK 3: Uruchamianie konfiguracji środowiska Python..."
sudo -u "$PROJECT_USER" bash -c "
set -e
echo '--- Tworzenie pliku .env z sekretami...'
cat > '$DEST_DIR/.env' <<EOF
SECRET_KEY=$(openssl rand -hex 32)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=$(openssl rand -hex 16)
FLASK_ENV=production
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/1
CELERY_RESULT_BACKEND=redis://localhost:6379/2
API_BEARER_TOKEN=$(openssl rand -base64 48)
RATELIMIT_STORAGE_URL=redis://localhost:6379/0
SESSION_TYPE=redis
EOF

echo '--- Tworzenie środowiska wirtualnego w $DEST_DIR/venv...'
python3 -m venv '$DEST_DIR/venv'
chmod -R +x '$DEST_DIR/venv/bin'

echo '--- Aktualizacja pip i instalacja zależności z requirements.txt...'
'$DEST_DIR/venv/bin/pip' install --upgrade pip
'$DEST_DIR/venv/bin/pip' install -r '$DEST_DIR/requirements.txt'

echo '--- Wykonywanie migracji bazy danych...'
# Pierwsze wdrożenie (odkomentuj przy initial deploy):
# '$DEST_DIR/venv/bin/flask' --app '$DEST_DIR/wsgi.py' db init || true
'$DEST_DIR/venv/bin/flask' --app '$DEST_DIR/wsgi.py' db migrate -m 'Enhanced v2.0.0 deployment migration' || true
'$DEST_DIR/venv/bin/flask' --app '$DEST_DIR/wsgi.py' db upgrade

echo '--- Optymalizacja bazy danych...'
'$DEST_DIR/venv/bin/flask' --app '$DEST_DIR/wsgi.py' optimize-db

echo '--- Sprawdzanie nowych funkcji...'
'$DEST_DIR/venv/bin/python' -c 'from api_utils import APIResponse; from schemas import LoginSchema; from cache_manager import cache_manager; print(\"✅ Nowe funkcje załadowane pomyślnie\")'
"

# --- KROK 4: Konfiguracja usługi Systemd dla Gunicorn ---
echo ">>> KROK 4: Konfiguracja usługi Systemd dla Gunicorn..."
sudo rm -f /etc/systemd/system/${SERVICE_NAME}.service
sudo tee /etc/systemd/system/${SERVICE_NAME}.service > /dev/null <<EOF
[Unit]
Description=Gunicorn instance to serve Enhanced Mobywatel Creator v2.0.0
After=network.target redis-server.service
Requires=redis-server.service

[Service]
User=$PROJECT_USER
Group=$PROJECT_USER
WorkingDirectory=$DEST_DIR
EnvironmentFile=$DEST_DIR/.env
Environment="PATH=$DEST_DIR/venv/bin"
Environment="FLASK_ENV=production"
Environment="REDIS_URL=redis://localhost:6379/0"
Environment="CELERY_BROKER_URL=redis://localhost:6379/1"
Environment="CELERY_RESULT_BACKEND=redis://localhost:6379/2"
ExecStart=$DEST_DIR/venv/bin/gunicorn --workers $GUNICORN_WORKERS --bind unix:$DEST_DIR/${SERVICE_NAME}.sock -m 007 --access-logfile $DEST_DIR/logs/gunicorn_access.log --error-logfile $DEST_DIR/logs/gunicorn_error.log wsgi:application
ExecReload=/bin/kill -s HUP \$MAINPID
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# --- KROK 4.5: Konfiguracja Celery Worker ---
echo ">>> KROK 4.5: Konfiguracja Celery Worker..."
sudo rm -f /etc/systemd/system/${SERVICE_NAME}-celery.service
sudo tee /etc/systemd/system/${SERVICE_NAME}-celery.service > /dev/null <<EOF
[Unit]
Description=Celery Worker for Enhanced Mobywatel Creator
After=network.target redis-server.service
Requires=redis-server.service

[Service]
User=$PROJECT_USER
Group=$PROJECT_USER
WorkingDirectory=$DEST_DIR
EnvironmentFile=$DEST_DIR/.env
Environment="PATH=$DEST_DIR/venv/bin"
Environment="FLASK_ENV=production"
Environment="REDIS_URL=redis://localhost:6379/0"
Environment="CELERY_BROKER_URL=redis://localhost:6379/1"
Environment="CELERY_RESULT_BACKEND=redis://localhost:6379/2"
ExecStart=$DEST_DIR/venv/bin/celery -A app.celery_app worker --loglevel=info --logfile=$DEST_DIR/celery_logs/worker.log
ExecReload=/bin/kill -s HUP \$MAINPID
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# --- KROK 4.6: Konfiguracja Celery Beat ---
echo ">>> KROK 4.6: Konfiguracja Celery Beat..."
sudo rm -f /etc/systemd/system/${SERVICE_NAME}-beat.service
sudo tee /etc/systemd/system/${SERVICE_NAME}-beat.service > /dev/null <<EOF
[Unit]
Description=Celery Beat for Enhanced Mobywatel Creator
After=network.target redis-server.service
Requires=redis-server.service

[Service]
User=$PROJECT_USER
Group=$PROJECT_USER
WorkingDirectory=$DEST_DIR
EnvironmentFile=$DEST_DIR/.env
Environment="PATH=$DEST_DIR/venv/bin"
Environment="FLASK_ENV=production"
Environment="REDIS_URL=redis://localhost:6379/0"
Environment="CELERY_BROKER_URL=redis://localhost:6379/1"
Environment="CELERY_RESULT_BACKEND=redis://localhost:6379/2"
ExecStart=$DEST_DIR/venv/bin/celery -A app.celery_app beat --loglevel=info --logfile=$DEST_DIR/celery_logs/beat.log
ExecReload=/bin/kill -s HUP \$MAINPID
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# --- KROK 4.7: Tworzenie dedykowanego pliku z nagłówkami bezpieczeństwa ---
echo ">>> KROK 4.7: Tworzenie pliku z nagłówkami bezpieczeństwa..."
sudo mkdir -p /etc/nginx/snippets
sudo tee /etc/nginx/snippets/security-headers.conf > /dev/null <<EOF
# HSTS (max-age = 2 lata), wymusza HTTPS
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
# Ochrona przed MIME sniffing
add_header X-Content-Type-Options "nosniff" always;
# X-Frame-Options ustawiany przez aplikację (DENY); pominięty w Nginx aby uniknąć konfliktów
# add_header X-Frame-Options "SAMEORIGIN" always;
# Ulepszona polityka Referrer
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
# Blokowanie niechcianych funkcji przeglądarki
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
# Polityka bezpieczeństwa treści jest ustawiana dynamicznie przez aplikację (CSP z nonce)
EOF

# --- KROK 5: Konfiguracja Nginx (WSTĘPNA, tylko HTTP) ---
echo ">>> KROK 5: Tworzenie WSTĘPNEJ konfiguracji Nginx dla domeny $DOMAIN (tylko port 80)..."
sudo rm -f /etc/nginx/sites-available/$SERVICE_NAME
sudo rm -f /etc/nginx/sites-enabled/$SERVICE_NAME

# Tym razem tworzymy BARDZO prostą konfigurację, bez żadnych nagłówków.
# Chodzi tylko o to, żeby Certbot ją znalazł i poprawnie zmodyfikował.
sudo tee /etc/nginx/sites-available/$SERVICE_NAME > /dev/null <<EOF
server {
    listen 80;
    server_name $DOMAIN;
    
    # Logi
    access_log /var/log/nginx/${SERVICE_NAME}_access.log;
    error_log /var/log/nginx/${SERVICE_NAME}_error.log;
    
    # Maksymalny rozmiar uploadu
    client_max_body_size 50M;
    
    location / {
        proxy_pass http://unix:$DEST_DIR/${SERVICE_NAME}.sock;
        proxy_set_header Host $$host;
        proxy_set_header X-Real-IP $$remote_addr;
        proxy_set_header X-Forwarded-For $$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $$scheme;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # Statyczne pliki
    location /static/ {
        alias $DEST_DIR/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
EOF

# Włącz nową konfigurację i usuń domyślną
sudo ln -sf /etc/nginx/sites-available/$SERVICE_NAME /etc/nginx/sites-enabled/
if [ -f /etc/nginx/sites-enabled/default ]; then
    sudo rm /etc/nginx/sites-enabled/default
fi

# --- KROK 6: Uruchomienie usług ---
echo ">>> KROK 6: Przeładowanie i uruchomienie usług..."
sudo systemctl daemon-reload

# Uruchomienie Celery services
echo ">>> Uruchamianie Celery Worker..."
sudo systemctl restart ${SERVICE_NAME}-celery
sudo systemctl enable ${SERVICE_NAME}-celery

echo ">>> Uruchamianie Celery Beat..."
sudo systemctl restart ${SERVICE_NAME}-beat
sudo systemctl enable ${SERVICE_NAME}-beat

# Uruchomienie głównej aplikacji
echo ">>> Uruchamianie głównej aplikacji..."
sudo systemctl restart $SERVICE_NAME
sudo systemctl enable $SERVICE_NAME

# Sprawdzenie konfiguracji Nginx i restart
echo ">>> Sprawdzanie i restartowanie Nginx..."
sudo nginx -t
sudo systemctl restart nginx

# --- KROK 7: Konfiguracja SSL i HTTP/2 za pomocą Certbota ---
echo ">>> KROK 7: Uruchamianie Certbota dla $DOMAIN..."
sudo certbot --nginx --non-interactive --agree-tos -m "$SSL_EMAIL" -d "$DOMAIN" --redirect

# ==============================================================================
# OSTATECZNA POPRAWKA: Wstrzykujemy nasze nagłówki PO tym, jak Certbot skończył pracę.
# ==============================================================================
echo ">>> KROK 8: Wstrzykiwanie ostatecznych nagłówków bezpieczeństwa do konfiguracji SSL..."
CONFIG_FILE="/etc/nginx/sites-available/$SERVICE_NAME"
# Używamy sed do wstawienia linii 'include ...' zaraz po linii 'server_name ...'
sudo sed -i "/server_name $DOMAIN/a include /etc/nginx/snippets/security-headers.conf;" $CONFIG_FILE

# --- KROK 9: Ostateczny restart Nginx ---
echo ">>> KROK 9: Ostateczny restart Nginx w celu załadowania pancernych nagłówków..."
sudo systemctl restart nginx

# --- KROK 10: Sprawdzenie statusu usług ---
echo ">>> KROK 10: Sprawdzenie statusu wszystkich usług..."
echo "Status Redis:"
sudo systemctl status redis-server --no-pager -l

echo "Status Gunicorn:"
sudo systemctl status $SERVICE_NAME --no-pager -l

echo "Status Celery Worker:"
sudo systemctl status ${SERVICE_NAME}-celery --no-pager -l

echo "Status Celery Beat:"
sudo systemctl status ${SERVICE_NAME}-beat --no-pager -l

echo "Status Nginx:"
sudo systemctl status nginx --no-pager -l

# --- KROK 11: Test nowych funkcji ---
echo ">>> KROK 11: Test nowych funkcji API v2..."
sleep 5  # Poczekaj na pełne uruchomienie

# Test API v2
echo "Testowanie API v2..."
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" http://localhost/api/v2/stats || echo "API v2 test - aplikacja może wymagać logowania"

echo
echo "----------------------------------------------------"
echo "✅ WDROŻENIE ENHANCED MOBYWATEL CREATOR v2.0.0 ZAKOŃCZONE POMYŚLNIE!"
echo "Twoja strona powinna być dostępna pod adresem: https://$DOMAIN"
echo ""
echo "🎉 NOWE FUNKCJE WDROŻONE:"
echo "  ✅ API v2 z ujednoliconymi odpowiedziami"
echo "  ✅ Schemas walidacji (Marshmallow)"
echo "  ✅ Cache system (Redis + Memory fallback)"
echo "  ✅ Async tasks (Celery Worker + Beat)"
echo "  ✅ Database optimization z indeksami"
echo "  ✅ Pancerne nagłówki bezpieczeństwa"
echo ""
echo "🔧 USŁUGI URUCHOMIONE:"
echo "  - Gunicorn (główna aplikacja)"
echo "  - Redis (cache + broker)"
echo "  - Celery Worker (zadania asynchroniczne)"
echo "  - Celery Beat (scheduler zadań)"
echo "  - Nginx (reverse proxy + SSL)"
echo ""
echo "📊 MONITORING:"
echo "  - Logi aplikacji: $DEST_DIR/logs/"
echo "  - Logi Celery: $DEST_DIR/celery_logs/"
echo "  - Status usług: sudo systemctl status mobywatel*"
echo ""
echo "🔍 SPRAWDŹ BEZPIECZEŃSTWO:"
echo "  - https://securityheaders.com/?q=https://$DOMAIN"
echo "  - https://www.ssllabs.com/ssltest/analyze.html?d=$DOMAIN"
echo ""
echo "📚 DOKUMENTACJA:"
echo "  - API Examples: $DEST_DIR/API_EXAMPLES.md"
echo "  - Changelog: $DEST_DIR/CHANGELOG.md"
echo "  - Test Results: $DEST_DIR/TEST_RESULTS.md"
echo "----------------------------------------------------"
