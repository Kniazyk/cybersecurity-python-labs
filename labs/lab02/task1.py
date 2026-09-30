import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import ClassVar

PBKDF2_ITERATIONS = 600_000
SALT_SIZE_BYTES = 16

# латинська літера + ще 2..63 символи (разом 3-64),
# далі @ і домен щонайменше з однією крапкою.
EMAIL_PATTERN = re.compile(
    r"[A-Za-z][A-Za-z0-9_]{2,63}"
    r"@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"
)


class User:
    def __init__(
        self,
        username: str,
        email: str,
        role: str,
        password: str,
        active: bool = True,
    ) -> None:
        self.username = username
        self.email = email
        self.role = role
        self.active = active
        self.__password_hash = b""
        self.__password_salt = b""
        self.set_password(password)

    # email як property
    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        if not isinstance(value, str) or EMAIL_PATTERN.fullmatch(value) is None:
            raise ValueError(f"Некоректний email: {value!r}")
        self._email = value

    # робота з паролем
    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
        )

    def set_password(self, password: str) -> None:
        if not password:
            raise ValueError("Пароль не може бути порожнім")
        self.__password_salt = os.urandom(SALT_SIZE_BYTES)
        self.__password_hash = self._derive_key(password, self.__password_salt)

    def check_password(self, password: str) -> bool:
        candidate = self._derive_key(password, self.__password_salt)
        return hmac.compare_digest(candidate, self.__password_hash)

    def deactivate(self) -> None:
        self.active = False

    def __str__(self) -> str:
        return (
            f"User(username={self.username}, email={self.email}, "
            f"role={self.role}, active={self.active})"
        )


class Admin(User):
    """Адміністратор: користувач із набором дозволів (Is-A User)."""

    def __init__(
        self,
        username: str,
        email: str,
        password: str,
        role: str = "admin",
        permissions: list[str] | None = None,
        active: bool = True,
    ) -> None:
        super().__init__(username, email, role, password, active)
        self.permissions: set[str] = set(permissions) if permissions else set()

    def grant_permission(self, permission: str) -> None:
        if not isinstance(permission, str) or not permission.strip():
            raise ValueError("Дозвіл має бути непорожнім рядком")
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        return (
            f"Admin(username={self.username}, email={self.email}, "
            f"role={self.role}, active={self.active}, "
            f"permissions={sorted(self.permissions)})"
        )


class Session:
    """Сесія користувача: IP, час входу та останньої активності."""

    def __init__(self, ip: str) -> None:
        self.ip = ip
        now = datetime.now(timezone.utc)
        self.login_time = now
        self.last_activity = now

    def touch(self) -> None:
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            raise ValueError("timeout_sec має бути додатним числом")
        elapsed = datetime.now(timezone.utc) - self.last_activity
        return elapsed <= timedelta(seconds=timeout_sec)

    def __str__(self) -> str:
        return (
            f"Session(ip={self.ip}, login_time={self.login_time.isoformat()}, "
            f"last_activity={self.last_activity.isoformat()})"
        )


# Дозволені типи дій в журналі аудиту.
LOGIN_SUCCESS = "login_success"
LOGIN_FAILURE = "login_failure"
LOGOUT = "logout"


@dataclass
class AuditEntry:
    """Один запис журналу аудиту: коли, хто, яку дію виконав."""

    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """Журнал подій безпеки (вхід, невдалий вхід, вихід)."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def add_log(self, username: str, action: str) -> None:
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc),
            username=username,
            action=action,
        )
        self._entries.append(entry)

    def show_all(self) -> None:
        for entry in self._entries:
            print(f"[{entry.timestamp.isoformat()}] {entry.username} -> {entry.action}")


SESSION_TIMEOUT_SEC = 900


class UserAccount:
    """Обліковий запис: об'єднує User, Session та AuditLog (композиція)."""

    # Дозволені ключі для __getitem__ / __setitem__ та очікувані типи значень.
    _ALLOWED_FIELDS: ClassVar[dict[str, type]] = {
        "user": str,
        "email": str,
        "role": str,
        "active": bool,
    }

    def __init__(self, user: User, audit_log: AuditLog | None = None) -> None:
        self._user = user
        self._session: Session | None = None
        self._audit_log = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        if username != self._user.username:
            self._audit_log.add_log(username, LOGIN_FAILURE)
            return False

        if not self._user.active:
            self._audit_log.add_log(username, LOGIN_FAILURE)
            return False

        if not self._user.check_password(password):
            self._audit_log.add_log(username, LOGIN_FAILURE)
            return False

        self._session = Session(ip)
        self._session.touch()
        self._audit_log.add_log(username, LOGIN_SUCCESS)
        return True

    def is_authenticated(self) -> bool:
        if self._session is None:
            return False
        return self._session.is_active(SESSION_TIMEOUT_SEC)

    def logout(self) -> None:
        if self._session is not None:
            self._audit_log.add_log(self._user.username, LOGOUT)
            self._session = None

    @property
    def audit_log(self) -> AuditLog:
        return self._audit_log

    @property
    def session(self) -> Session | None:
        return self._session

    # __getitem__ / __setitem__
    def __getitem__(self, key: str):
        if key not in self._ALLOWED_FIELDS:
            raise KeyError(f"Невідомий ключ: {key!r}")
        if key == "user":
            return self._user.username
        return getattr(self._user, key)

    def __setitem__(self, key: str, value) -> None:
        if key not in self._ALLOWED_FIELDS:
            raise KeyError(f"Невідомий ключ: {key!r}")
        expected_type = self._ALLOWED_FIELDS[key]
        if not isinstance(value, expected_type):
            raise TypeError(
                f"Значення для {key!r} має бути типу {expected_type.__name__}"
            )
        if key == "user":
            self._user.username = value
        else:
            setattr(self._user, key, value)
