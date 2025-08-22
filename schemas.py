"""
Schemas walidacji - Marshmallow schemas dla walidacji danych wejściowych
"""
from marshmallow import Schema, fields, validate, ValidationError, validates_schema
from typing import Dict, Any
import re


class LoginSchema(Schema):
    """Schema dla logowania użytkownika"""
    username = fields.Str(
        required=True,
        validate=[
            validate.Length(min=3, max=50, error="Nazwa użytkownika musi mieć od 3 do 50 znaków"),
            validate.Regexp(r'^[a-zA-Z0-9_]+$', error="Nazwa użytkownika może zawierać tylko litery, cyfry i podkreślenia")
        ],
        error_messages={"required": "Nazwa użytkownika jest wymagana"}
    )
    password = fields.Str(
        required=True,
        validate=validate.Length(min=6, max=100, error="Hasło musi mieć od 6 do 100 znaków"),
        error_messages={"required": "Hasło jest wymagane"}
    )
    remember = fields.Bool(missing=False)


class RegisterSchema(Schema):
    """Schema dla rejestracji użytkownika"""
    username = fields.Str(
        required=True,
        validate=[
            validate.Length(min=3, max=50, error="Nazwa użytkownika musi mieć od 3 do 50 znaków"),
            validate.Regexp(r'^[a-zA-Z0-9_]+$', error="Nazwa użytkownika może zawierać tylko litery, cyfry i podkreślenia")
        ],
        error_messages={"required": "Nazwa użytkownika jest wymagana"}
    )
    password = fields.Str(
        required=True,
        validate=[
            validate.Length(min=6, max=100, error="Hasło musi mieć od 6 do 100 znaków"),
            validate.Regexp(
                r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]',
                error="Hasło musi zawierać wielkie litery, małe litery, cyfry i znaki specjalne"
            )
        ],
        error_messages={"required": "Hasło jest wymagane"}
    )
    confirm_password = fields.Str(
        required=True,
        error_messages={"required": "Potwierdzenie hasła jest wymagane"}
    )
    access_key = fields.Str(
        required=True,
        validate=validate.Length(min=1, error="Klucz dostępu jest wymagany"),
        error_messages={"required": "Klucz dostępu jest wymagany"}
    )
    referral_code = fields.Str(allow_none=True)

    @validates_schema
    def validate_passwords_match(self, data: Dict[str, Any], **kwargs):
        """Sprawdza czy hasła się zgadzają"""
        if data.get('password') != data.get('confirm_password'):
            raise ValidationError('Hasła nie są identyczne', 'confirm_password')


class PasswordResetSchema(Schema):
    """Schema dla resetowania hasła"""
    token = fields.Str(
        required=True,
        validate=validate.Length(min=1, error="Token jest wymagany"),
        error_messages={"required": "Token jest wymagany"}
    )
    new_password = fields.Str(
        required=True,
        validate=[
            validate.Length(min=6, max=100, error="Nowe hasło musi mieć od 6 do 100 znaków"),
            validate.Regexp(
                r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]',
                error="Hasło musi zawierać wielkie litery, małe litery, cyfry i znaki specjalne"
            )
        ],
        error_messages={"required": "Nowe hasło jest wymagane"}
    )


class ForgotPasswordSchema(Schema):
    """Schema dla funkcji 'zapomniałem hasła'"""
    username = fields.Str(
        required=True,
        validate=validate.Length(min=3, max=50, error="Nazwa użytkownika musi mieć od 3 do 50 znaków"),
        error_messages={"required": "Nazwa użytkownika jest wymagana"}
    )


class DocumentDataSchema(Schema):
    """Schema dla danych dokumentu"""
    user_name = fields.Str(
        required=True,
        validate=validate.Length(min=2, max=50, error="Nazwa użytkownika musi mieć od 2 do 50 znaków"),
        error_messages={"required": "Nazwa użytkownika jest wymagana"}
    )
    imie = fields.Str(
        required=True,
        validate=validate.Length(min=1, max=50, error="Imię musi mieć od 1 do 50 znaków"),
        error_messages={"required": "Imię jest wymagane"}
    )
    nazwisko = fields.Str(
        required=True,
        validate=validate.Length(min=1, max=50, error="Nazwisko musi mieć od 1 do 50 znaków"),
        error_messages={"required": "Nazwisko jest wymagane"}
    )
    obywatelstwo = fields.Str(
        required=True,
        validate=validate.Length(min=1, max=50, error="Obywatelstwo musi mieć od 1 do 50 znaków"),
        error_messages={"required": "Obywatelstwo jest wymagane"}
    )
    data_urodzenia = fields.Str(
        required=True,
        validate=validate.Regexp(
            r'^\d{2}\.\d{2}\.\d{4}$',
            error="Data urodzenia musi być w formacie DD.MM.YYYY"
        ),
        error_messages={"required": "Data urodzenia jest wymagana"}
    )
    pesel = fields.Str(
        required=True,
        validate=validate.Regexp(
            r'^\d{11}$',
            error="PESEL musi składać się z 11 cyfr"
        ),
        error_messages={"required": "PESEL jest wymagany"}
    )
    seria_numer_mdowodu = fields.Str(allow_none=True)
    termin_waznosci_mdowodu = fields.Str(allow_none=True)
    data_wydania_mdowodu = fields.Str(allow_none=True)
    imie_ojca_mdowod = fields.Str(allow_none=True)
    imie_matki_mdowod = fields.Str(allow_none=True)
    seria_numer_dowodu = fields.Str(allow_none=True)
    termin_waznosci_dowodu = fields.Str(allow_none=True)
    data_wydania_dowodu = fields.Str(allow_none=True)
    nazwisko_rodowe = fields.Str(allow_none=True)
    plec = fields.Str(
        validate=validate.OneOf(['M', 'K'], error="Płeć musi być 'M' lub 'K'"),
        allow_none=True
    )
    nazwisko_rodowe_ojca = fields.Str(allow_none=True)
    nazwisko_rodowe_matki = fields.Str(allow_none=True)
    miejsce_urodzenia = fields.Str(allow_none=True)
    adres_zameldowania = fields.Str(allow_none=True)
    data_zameldowania = fields.Str(allow_none=True)


class AdminLoginSchema(Schema):
    """Schema dla logowania administratora"""
    username = fields.Str(
        required=True,
        validate=validate.Length(min=1, error="Nazwa użytkownika jest wymagana"),
        error_messages={"required": "Nazwa użytkownika jest wymagana"}
    )
    password = fields.Str(
        required=True,
        validate=validate.Length(min=1, error="Hasło jest wymagane"),
        error_messages={"required": "Hasło jest wymagane"}
    )


class AnnouncementSchema(Schema):
    """Schema dla tworzenia ogłoszeń"""
    title = fields.Str(
        required=True,
        validate=validate.Length(min=1, max=200, error="Tytuł musi mieć od 1 do 200 znaków"),
        error_messages={"required": "Tytuł jest wymagany"}
    )
    message = fields.Str(
        required=True,
        validate=validate.Length(min=1, max=2000, error="Treść musi mieć od 1 do 2000 znaków"),
        error_messages={"required": "Treść jest wymagana"}
    )
    type = fields.Str(
        validate=validate.OneOf(['info', 'warning', 'error', 'success'], error="Nieprawidłowy typ ogłoszenia"),
        missing='info'
    )
    expires_at = fields.DateTime(allow_none=True)


class AccessKeySchema(Schema):
    """Schema dla generowania kluczy dostępu"""
    description = fields.Str(
        validate=validate.Length(max=200, error="Opis może mieć maksymalnie 200 znaków"),
        allow_none=True
    )
    validity_days = fields.Int(
        validate=validate.Range(min=1, max=365, error="Ważność musi być od 1 do 365 dni"),
        missing=30
    )


class UserManagementSchema(Schema):
    """Schema dla zarządzania użytkownikami"""
    username = fields.Str(
        required=True,
        validate=validate.Length(min=3, max=50, error="Nazwa użytkownika musi mieć od 3 do 50 znaków"),
        error_messages={"required": "Nazwa użytkownika jest wymagana"}
    )
    amount = fields.Int(
        required=True,
        validate=validate.Range(min=-1000, max=1000, error="Kwota musi być między -1000 a 1000"),
        error_messages={"required": "Kwota jest wymagana"}
    )


class PaginationSchema(Schema):
    """Schema dla paginacji"""
    page = fields.Int(
        validate=validate.Range(min=1, error="Strona musi być większa od 0"),
        missing=1
    )
    per_page = fields.Int(
        validate=validate.Range(min=1, max=100, error="Liczba elementów na stronę musi być od 1 do 100"),
        missing=10
    )


# Funkcje pomocnicze do walidacji
def validate_pesel(pesel: str) -> bool:
    """Walidacja numeru PESEL"""
    if not re.match(r'^\d{11}$', pesel):
        return False
    
    # Sprawdzenie sumy kontrolnej
    weights = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3]
    checksum = sum(int(pesel[i]) * weights[i] for i in range(10))
    checksum = (10 - (checksum % 10)) % 10
    
    return checksum == int(pesel[10])


def validate_date_format(date_str: str) -> bool:
    """Walidacja formatu daty DD.MM.YYYY"""
    if not re.match(r'^\d{2}\.\d{2}\.\d{4}$', date_str):
        return False
    
    try:
        day, month, year = map(int, date_str.split('.'))
        if not (1 <= day <= 31 and 1 <= month <= 12 and 1900 <= year <= 2100):
            return False
        return True
    except ValueError:
        return False


# Schemas dla różnych typów żądań
login_schema = LoginSchema()
register_schema = RegisterSchema()
password_reset_schema = PasswordResetSchema()
forgot_password_schema = ForgotPasswordSchema()
document_data_schema = DocumentDataSchema()
admin_login_schema = AdminLoginSchema()
announcement_schema = AnnouncementSchema()
access_key_schema = AccessKeySchema()
user_management_schema = UserManagementSchema()
pagination_schema = PaginationSchema()
