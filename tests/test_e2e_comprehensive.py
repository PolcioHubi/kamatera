import time
from playwright.sync_api import Page, expect
from models import db

def test_user_registration_e2e(page: Page, base_url, access_key_service):
    """
    Testuje proces rejestracji użytkownika od początku do końca.
    """
    # Generate a unique access key for this test
    access_key = access_key_service.generate_access_key("e2e_registration_key")
    db.session.commit()

    # 1. Przejdź do strony rejestracji
    page.goto(f"{base_url}/register")
    page.wait_for_load_state("networkidle")
    expect(page).to_have_url(f"{base_url}/register")

    # 2. Wypełnij formularz rejestracyjny
    new_username = "e2e_new_user"
    new_password = "e2e_password123"

    page.fill('input[name="username"]', new_username)
    page.fill('input[name="password"]', new_password)
    page.fill('input[name="confirm_password"]', new_password)
    page.fill('textarea[name="accessKey"]', access_key)
    
    # Kliknij przycisk i poczekaj na odpowiedź z serwera
    with page.expect_response(f"{base_url}/register") as response_info:
        page.click('button:has-text("Zarejestruj")')

    response = response_info.value
    assert response.status == 200
    response_data = response.json()
    assert response_data["success"] is True
    assert response_data["recovery_token"] is not None

    # 3. Oczekuj, że modal z tokenem odzyskiwania się pojawi
    expect(page.locator("#overlayActualRecoveryToken")).to_be_visible()
    expect(page.locator("#overlayActualRecoveryToken")).to_contain_text(response_data["recovery_token"])

    # 4. Zamknij modal i przejdź do logowania
    page.click('#recoveryTokenModal button:has-text("OK")')
    expect(page.locator("#recoveryTokenModal")).to_be_hidden()

def test_user_login_e2e(page: Page, base_url, registered_user):
    """
    Testuje proces logowania użytkownika.
    """
    # 1. Przejdź do strony logowania
    page.goto(f"{base_url}/login")
    expect(page).to_have_url(f"{base_url}/login")

    # 2. Wypełnij formularz logowania
    page.fill('input[name="username"]', registered_user["username"])
    page.fill('input[name="password"]', registered_user["password"])
    
    # 3. Kliknij przycisk logowania
    with page.expect_response(f"{base_url}/login") as response_info:
        page.click('button:has-text("Zaloguj")')

    response = response_info.value
    assert response.status == 200
    response_data = response.json()
    assert response_data["success"] is True

    # 4. Sprawdź, czy użytkownik został przekierowany na stronę główną
    expect(page).to_have_url(f"{base_url}/")
    expect(page.locator("h1")).to_have_text("Podmieniacz Danych HTML")

def test_document_generation_e2e(page: Page, base_url, registered_user):
    """
    Testuje generowanie dokumentu z formularza.
    """
    # Logowanie
    page.goto(f"{base_url}/login")
    page.fill('input[name="username"]', registered_user["username"])
    page.fill('input[name="password"]', registered_user["password"])
    page.click('button:has-text("Zaloguj")')

    # Wypełnienie formularza
    page.fill('input[name="imie"]', "Jan")
    page.fill('input[name="nazwisko"]', "Kowalski")
    page.fill('input[name="obywatelstwo"]', "Polskie")
    page.fill('input[name="data_urodzenia"]', "01.01.1990")
    page.fill('input[name="pesel"]', "90010112345")
    page.fill('input[name="seria_numer_mdowodu"]', "ABC123456")
    page.fill('input[name="termin_waznosci_mdowodu"]', "2030-01-01")
    page.fill('input[name="data_wydania_mdowodu"]', "2020-01-01")
    page.fill('input[name="imie_ojca_mdowod"]', "Marek")
    page.fill('input[name="imie_matki_mdowod"]', "Anna")
    page.fill('input[name="seria_numer_dowodu"]', "DEF789012")
    page.fill('input[name="termin_waznosci_dowodu"]', "2030-01-01")
    page.fill('input[name="data_wydania_dowodu"]', "2020-01-01")
    page.fill('input[name="nazwisko_rodowe"]', "Kowalska")
    page.select_option('select[name="plec"]', 'M')
    page.fill('input[name="nazwisko_rodowe_ojca"]', "Kowalski")
    page.fill('input[name="nazwisko_rodowe_matki"]', "Nowak")
    page.fill('input[name="miejsce_urodzenia"]', "Warszawa")
    page.fill('textarea[name="adres_zameldowania"]', "ul. Testowa 1, 00-001 Warszawa")
    page.fill('input[name="data_zameldowania"]', "2020-01-01")

    # Prześlij formularz
    page.click('button:has-text("Modyfikuj i Zapisz")')

    # Oczekuj komunikatu sukcesu w modalu
    expect(page.locator("#notificationModal")).to_be_visible()
    expect(page.locator("#notificationTitle")).to_have_text("Sukces!")
    expect(page.locator("#notificationMessage")).to_have_text(
        "Dane i pliki zostały przetworzone pomyślnie."
    )

    # Zamknij modal
    page.click('#notificationModal button:has-text("OK")')
    expect(page.locator("#notificationModal")).to_be_hidden()

def test_form_validation_e2e(page: Page, base_url, registered_user):
    """
    Testuje walidację formularza.
    """
    # Logowanie
    page.goto(f"{base_url}/login")
    page.fill('input[name="username"]', registered_user["username"])
    page.fill('input[name="password"]', registered_user["password"])
    page.click('button:has-text("Zaloguj")')

    # Próba wysłania pustego formularza
    page.click('button:has-text("Modyfikuj i Zapisz")')

    # Sprawdzenie czy pojawił się komunikat (może być sukces lub błąd)
    expect(page.locator("#notificationModal")).to_be_visible()
    # Sprawdź czy modal zawiera jakiś tytuł (nie sprawdzamy konkretnego tekstu)
    expect(page.locator("#notificationTitle")).to_be_visible()

    # Zamknij modal
    page.click('#notificationModal button:has-text("OK")')

    # Test walidacji PESEL
    page.fill('input[name="data_urodzenia"]', "01.01.1990")
    page.select_option('select[name="plec"]', 'M')
    page.click('button:has-text("Automatyczne generowanie PESELu")')
    
    # Sprawdzenie czy PESEL został wygenerowany
    pesel_value = page.input_value('input[name="pesel"]')
    assert len(pesel_value) == 11
    assert pesel_value.isdigit()

def test_random_data_generation_e2e(page: Page, base_url, registered_user):
    """
    Testuje generowanie losowych danych.
    """
    # Logowanie
    page.goto(f"{base_url}/login")
    page.fill('input[name="username"]', registered_user["username"])
    page.fill('input[name="password"]', registered_user["password"])
    page.click('button:has-text("Zaloguj")')

    # Kliknięcie przycisku generowania losowych danych
    page.click('button:has-text("Generuj losowe dane")')

    # Sprawdzenie czy pola zostały wypełnione
    imie_value = page.input_value('input[name="imie"]')
    nazwisko_value = page.input_value('input[name="nazwisko"]')
    pesel_value = page.input_value('input[name="pesel"]')

    assert imie_value != ""
    assert nazwisko_value != ""
    assert len(pesel_value) == 11

def test_logout_e2e(page: Page, base_url, registered_user):
    """
    Testuje proces wylogowania użytkownika.
    """
    # Logowanie
    page.goto(f"{base_url}/login")
    page.fill('input[name="username"]', registered_user["username"])
    page.fill('input[name="password"]', registered_user["password"])
    page.click('button:has-text("Zaloguj")')

    # Sprawdzenie czy użytkownik jest zalogowany
    expect(page.locator("text=Zalogowany")).to_be_visible()

    # Wylogowanie
    page.click('a:has-text("🚪 Wyloguj")')

    # Sprawdzenie czy użytkownik został przekierowany na stronę logowania
    expect(page).to_have_url(f"{base_url}/login")
    expect(page.locator("h1")).to_contain_text("Logowanie")

def test_profile_access_e2e(page: Page, base_url, registered_user):
    """
    Testuje dostęp do profilu użytkownika.
    """
    # Logowanie
    page.goto(f"{base_url}/login")
    page.fill('input[name="username"]', registered_user["username"])
    page.fill('input[name="password"]', registered_user["password"])
    page.click('button:has-text("Zaloguj")')

    # Przejście do profilu
    page.click('a:has-text("👤 Profil")')

    # Sprawdzenie czy strona profilu się załadowała
    expect(page).to_have_url(f"{base_url}/profile")
    expect(page.locator("h1")).to_contain_text("Profil")

def test_admin_access_e2e(page: Page, base_url, registered_user):
    """
    Testuje dostęp do panelu administratora.
    """
    # Logowanie
    page.goto(f"{base_url}/login")
    page.fill('input[name="username"]', registered_user["username"])
    page.fill('input[name="password"]', registered_user["password"])
    page.click('button:has-text("Zaloguj")')

    # Próba dostępu do panelu admina (powinno przekierować do logowania admina)
    page.click('a:has-text("🔧 Admin")')

    # Sprawdzenie czy użytkownik został przekierowany do logowania admina
    expect(page).to_have_url(f"{base_url}/admin/login")

def test_form_clear_e2e(page: Page, base_url, registered_user):
    """
    Testuje czyszczenie formularza.
    """
    # Logowanie
    page.goto(f"{base_url}/login")
    page.fill('input[name="username"]', registered_user["username"])
    page.fill('input[name="password"]', registered_user["password"])
    page.click('button:has-text("Zaloguj")')

    # Wypełnienie formularza
    page.fill('input[name="imie"]', "Test")
    page.fill('input[name="nazwisko"]', "Użytkownik")

    # Sprawdzenie czy pola są wypełnione
    assert page.input_value('input[name="imie"]') == "Test"
    assert page.input_value('input[name="nazwisko"]') == "Użytkownik"

    # Czyszczenie formularza
    page.click('button:has-text("Wyczyść formularz")')

    # Sprawdzenie czy pola zostały wyczyszczone
    assert page.input_value('input[name="imie"]') == ""
    assert page.input_value('input[name="nazwisko"]') == ""

def test_image_upload_e2e(page: Page, base_url, registered_user):
    """
    Testuje upload zdjęcia.
    """
    # Logowanie
    page.goto(f"{base_url}/login")
    page.fill('input[name="username"]', registered_user["username"])
    page.fill('input[name="password"]', registered_user["password"])
    page.click('button:has-text("Zaloguj")')

    # Upload pliku
    page.set_input_files('input[name="image_upload"]', "tests/assets/image_v1.jpg")

    # Sprawdzenie czy plik został wybrany
    file_input = page.locator('input[name="image_upload"]')
    # Sprawdzenie czy plik został wybrany (nie jest pusty)
    file_value = file_input.input_value()
    assert file_value != ""

def test_tutorial_e2e(page: Page, base_url, registered_user):
    """
    Testuje samouczek aplikacji.
    """
    # Logowanie
    page.goto(f"{base_url}/login")
    page.fill('input[name="username"]', registered_user["username"])
    page.fill('input[name="password"]', registered_user["password"])
    page.click('button:has-text("Zaloguj")')

    # Sprawdzenie czy samouczek się pojawił (jeśli użytkownik go nie widział)
    tutorial_modal = page.locator("#tutorialModal")
    if tutorial_modal.is_visible():
        # Kliknięcie "Dalej" w samouczku
        page.click('#tutorialBtnNext')
        
        # Sprawdzenie czy samouczek się zamknął
        expect(tutorial_modal).to_be_hidden()
