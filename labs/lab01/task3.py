import csv
import hashlib
import json
import os
import sys
from datetime import datetime
from functools import wraps

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../../")
    )
)

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

MIN_PASSWORD_LENGTH = 10
SALT = str(VARIANT_NUMBER).zfill(5)

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
USERS_CSV_PATH = os.path.join(DATA_DIR, "users.csv")
LOG_JSON_PATH = os.path.join(DATA_DIR, "log.json")


class ValidationError(Exception):

    pass


def generate_hash(password: str, salt: str = "00000") -> str:
    if password is None or salt is None or password == "" or salt == "":
        raise ValueError("Пароль або сіль не можуть бути порожніми")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль коротший за мінімальну довжину ({MIN_PASSWORD_LENGTH} символів)"
        )

    data_to_hash = (password + salt).encode("utf-8")
    return hashlib.sha3_384(data_to_hash).hexdigest()


def log_event(func):

    @wraps(func)
    def wrapper(username, password, *args, **kwargs):
        try:
            res = func(username, password, *args, **kwargs)
            result_str = "success" if res else "failure"
        except Exception as e:
            result_str = "failure"
            raise e
        finally:
            log_entry = {
                "event": "login",
                "user": username,
                "result": locals().get("result_str", "failure"),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "args": list(args),
                "kwargs": kwargs,
            }

            os.makedirs(DATA_DIR, exist_ok=True)
            logs = []
            if os.path.exists(LOG_JSON_PATH):
                try:
                    with open(LOG_JSON_PATH, "r", encoding="utf-8") as f:
                        logs = json.load(f)
                except (json.JSONDecodeError, IOError):
                    logs = []

            logs.append(log_entry)
            with open(LOG_JSON_PATH, "w", encoding="utf-8") as f:
                json.dump(logs, f, ensure_ascii=False, indent=4)

        return res

    return wrapper


def create_user(username: str, password: str) -> tuple:
    hash_val = generate_hash(password, SALT)
    return (username, hash_val)


def create_users(users_list: list):

    os.makedirs(DATA_DIR, exist_ok=True)
    valid_users = []

    for un, pw in users_list:
        try:
            user_tuple = create_user(un, pw)
            valid_users.append(user_tuple)
        except (ValueError, ValidationError) as e:
            print(f"Помилка реєстрації користувача {un}: {e}")

    with open(USERS_CSV_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["username", "hash_value"])
        writer.writerows(valid_users)


def read_users_db() -> list:
    if not os.path.exists(USERS_CSV_PATH):
        raise FileNotFoundError(f"Файл {USERS_CSV_PATH} не знайдено.")

    users_db = []
    with open(USERS_CSV_PATH, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader, None)
        for row in reader:
            if row:
                users_db.append(row)
    return users_db


@log_event
def login(username: str, password: str) -> bool:

    if not username or not password:
        raise ValueError("Логін та пароль не можуть бути порожніми")

    users_db = read_users_db()
    try:
        input_hash = generate_hash(password, SALT)
    except ValidationError:
        return False

    for db_user, db_hash in users_db:
        if db_user == username and db_hash == input_hash:
            return True

    return False


def run_task3():
    print(
        f"=== Завдання 3 | Студент: {STUDENT_NAME} ({GROUP_NAME}), Варіант {VARIANT_NUMBER} ==="
    )

    users_to_register = (
        ("admin_user", "Admin#2026Secure"),
        ("sec_officer", "Phish1ng@D3tect"),
        ("dev_lead", "Ransomwar3@Protect"),
        ("analyst_01", "S0cial@Engineer"),
        ("guest_account", "12345"),
        ("auditor", "Audit@2026Pass"),
        ("net_admin", "Cisco@Packet2026"),
        ("db_admin", "DataBase#Pass1"),
        ("crypto_user", "Crypto@D3tect"),
        ("test_user", "TestingPass123"),
    )

    try:
        print("\n1. Реєстрація користувачів та збереження в CSV...")
        create_users(users_to_register)

        print("\n2. Зчитування бази даних з CSV:")
        db = read_users_db()
        print(f"{'Username':<15} | {'SHA3-384 Hash (перші 30 симв.)':<35}")
        print("-" * 55)
        for u, h in db:
            print(f"{u:<15} | {h[:30]}...")

        print("\n3. Тестування входу (автентифікація):")
        test_logins = [
            ("admin_user", "Admin#2026Secure"),  # Успішно
            ("sec_officer", "WrongPassword"),  # Невірний пароль
            ("unknown_user", "SomePass12345"),  # Немає користувача
        ]

        for u, p in test_logins:
            status = login(u, p)
            res_str = "УСПІШНО" if status else "ВІДМОВА"
            print(f"Спроба входу user=[{u}] -> {res_str}")

    except (
        FileNotFoundError,
        PermissionError,
        IOError,
        ValidationError,
        ValueError,
    ) as err:
        print(f"\n[ПОМИЛКА ОБРОБКИ]: {err}")


if __name__ == "__main__":
    run_task3()