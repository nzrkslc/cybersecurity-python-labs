import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

PBKDF2_ITERATIONS = 100_000


class User:
    """Клас моделі користувача з безпечним збереженням пароля та валидацією email."""

    def __init__(
        self, username: str, email: str, role: str = "user", active: bool = True
    ) -> None:
        self.username = username
        self.role = role
        self.active = active
        self._email = ""
        self.email = email  # Виклик сеттера для перевірки
        self.__password_hash: bytes = b""
        self.__password_salt: bytes = b""

    @property
    def email(self) -> str:
        """Геттер email адреси."""
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        """Сеттер email з перевіркою формату за допомогою регулярних виразів."""
        pattern = r"^[a-zA-Z][a-zA-Z0-9._]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, value):
            raise ValueError(f"Некоректний формат email адреси: {value}")
        self._email = value

    def set_password(self, password: str) -> None:
        """Встановлює пароль із генеруванням випадкової солі та PBKDF2-HMAC-SHA256."""
        if not password or len(password) < 8:
            raise ValueError("Пароль повинен містити щонайменше 8 символів.")
        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.__password_salt, PBKDF2_ITERATIONS
        )

    def check_password(self, password: str) -> bool:
        """Перевіряє відповідність пароля за допомогою безаварійного порівняння хешів."""
        if not self.__password_hash or not self.__password_salt:
            return False
        computed_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.__password_salt, PBKDF2_ITERATIONS
        )
        return hmac.compare_digest(self.__password_hash, computed_hash)

    def deactivate(self) -> None:
        """Деактивує обліковий запис."""
        self.active = False

    def __str__(self) -> str:
        status = "Active" if self.active else "Inactive"
        return (
            f"User(username='{self.username}', role='{self.role}', status='{status}')"
        )


class Admin(User):
    """Клас адміністратора, що розширює User правом керування дозволами (Наслідування)."""

    def __init__(
        self,
        username: str,
        email: str,
        permissions: set[str] | list[str] | None = None,
        active: bool = True,
    ) -> None:
        super().__init__(username, email, role="admin", active=active)
        self.permissions: set[str] = set(permissions) if permissions else set()

    def grant_permission(self, permission: str) -> None:
        """Надає привілею адміністратору."""
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        """Вилучає привілею у адміністратора."""
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        """Перевіряє наявність привілеї."""
        return permission in self.permissions

    def __str__(self) -> str:
        base_str = super().__str__()
        perms = ", ".join(sorted(self.permissions)) if self.permissions else "None"
        return f"{base_str} [Permissions: {perms}]"


class Session:
    """Модель сесії користувача з контролем таймауту активності."""

    def __init__(self, ip: str) -> None:
        self.ip = ip
        now = datetime.now(timezone.utc)
        self.login_time: datetime = now
        self.last_activity: datetime = now

    def touch(self) -> None:
        """Оновлює час останньої активності сесії."""
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        """Перевіряє, чи активна сесія відносно заданого таймауту."""
        if timeout_sec <= 0:
            raise ValueError(
                "Значення timeout_sec повинно бути позитивним цілим числом."
            )
        elapsed = (datetime.now(timezone.utc) - self.last_activity).total_seconds()
        return elapsed < timeout_sec


@dataclass
class AuditRecord:
    """Структура запису журналу аудиту."""

    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """Журнал аудиту дій користувачів."""

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []

    def add_log(self, username: str, action: str) -> None:
        """Додає новий запис аудиту з поточним UTC-часом."""
        record = AuditRecord(
            timestamp=datetime.now(timezone.utc), username=username, action=action
        )
        self._records.append(record)

    def show_all(self) -> list[AuditRecord]:
        """Повертає всі записи аудиту."""
        return list(self._records)


class UserAccount:
    """Обліковий запис, що об'єднує User, Session та AuditLog (Композиція)."""

    SESSION_TIMEOUT_SEC = 900

    def __init__(
        self,
        user: User,
        session: Session | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        self.user = user
        self.session = session
        self.audit_log = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        """Автентифікація користувача та відкриття сесії."""
        if username != self.user.username or not self.user.active:
            self.audit_log.add_log(username, "login_failure")
            return False

        if self.user.check_password(password):
            self.session = Session(ip=ip)
            self.session.touch()
            self.audit_log.add_log(username, "login_success")
            return True

        self.audit_log.add_log(username, "login_failure")
        return False

    def is_authenticated(self) -> bool:
        """Перевіряє чи є активна та чинна сесія."""
        if self.session is None:
            return False
        return self.session.is_active(self.SESSION_TIMEOUT_SEC)

    def logout(self) -> None:
        """Завершує сесію та реєструє подію."""
        if self.user:
            self.audit_log.add_log(self.user.username, "logout")
        self.session = None

    def __getitem__(self, key: str) -> Any:
        allowed = {
            "user": self.user,
            "session": self.session,
            "audit_log": self.audit_log,
        }
        if key in allowed:
            return allowed[key]
        raise KeyError(f"Доступ до ключа '{key}' заборонено або ключ відсутній.")

    def __setitem__(self, key: str, value: Any) -> None:
        if key == "user":
            if not isinstance(value, User):
                raise TypeError("Значення для 'user' має бути екземпляром класу User.")
            self.user = value
        elif key == "session":
            if value is not None and not isinstance(value, Session):
                raise TypeError(
                    "Значення для 'session' має бути екземпляром класу Session або None."
                )
            self.session = value
        elif key == "audit_log":
            if not isinstance(value, AuditLog):
                raise TypeError(
                    "Значення для 'audit_log' має бути екземпляром класу AuditLog."
                )
            self.audit_log = value
        else:
            raise KeyError(f"Неможливо встановити атрибут з ключем '{key}'.")


def run_demo() -> None:
    """Демонстраційний сценарій для Завдання 1."""
    print("=== Демонстрація Завдання 1 (ООП Модель) ===")

    # 1. Створення користувача та Admin
    user = User("j_doe", "j_doe@corp.ua")
    user.set_password("SecureP@ss123")
    admin = Admin("admin_alex", "alex@corp.ua", permissions={"read", "write"})
    admin.set_password("AdminStrongPass2026!")

    print(f"Створено користувача: {user}")
    print(f"Створено адміністратора: {admin}")

    # 2. Перевірка валідації Email
    try:
        user.email = "bad_email_at_domain"
    except ValueError as e:
        print(f"[OK] Спіймано очікувану помилку валідації email: {e}")

    # 3. Аутентифікація через UserAccount (Композиція)
    account = UserAccount(user)
    print("\n--- Спроба входу з неправильним паролем ---")
    success = account.login("j_doe", "wrong_pass", "192.168.1.100")
    print(
        f"Результат входу: {success} | Статус автентифікації: {account.is_authenticated()}"
    )

    print("\n--- Спроба входу з правильним паролем ---")
    success = account.login("j_doe", "SecureP@ss123", "192.168.1.100")
    print(
        f"Результат входу: {success} | Статус автентифікації: {account.is_authenticated()}"
    )

    # 4. Перевірка роботи __getitem__
    print(f"\nПеревірка __getitem__: account['user'] -> {account['user']}")

    # 5. Вихід
    account.logout()
    print(f"Після logout() статус автентифікації: {account.is_authenticated()}")

    # 6. Журнал аудиту
    print("\n=== Записи AuditLog ===")
    for log in account.audit_log.show_all():
        print(
            f"[{log.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}] Користувач: {log.username} | Дія: {log.action}"
        )
