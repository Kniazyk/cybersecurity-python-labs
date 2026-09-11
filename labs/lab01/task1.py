import os
import random
import sys

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../../")
    )
)

from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER

passwords = [
    "S0cial@Engineer",
    "basic",
    "Phish1ng@D3tect",
    "client",
    "Ransomwar3@Protect",
    "general",
    "Zero@D4y",
    "generic",
    "Bug@B0unty",
    "standard123",
]

criteria = {
    "min_length": 11,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

forbidden_passwords = {
    "basic",
    "client",
    "general",
    "generic",
    "standard123",
    "guest",
}


def analyze_password(pwd: str, all_pwds: list) -> str:
    if pwd in forbidden_passwords:  # Перевірка на список заборонених
        return "Заборонений"

    min_len = criteria["min_length"]
    has_digit = any(c.isdigit() for c in pwd)
    has_upper = any(c.isupper() for c in pwd)
    has_lower = any(c.islower() for c in pwd)
    has_spec = any(not c.isalnum() for c in pwd)

    # Перевірка виконання всіх обов'язкових критеріїв
    all_criteria_met = (
            len(pwd) >= min_len and has_digit and has_upper and has_spec
    )
    is_unique = all_pwds.count(pwd) == 1

    if len(pwd) < min_len:
        return "Слабкий (короткий)"

    if all_criteria_met:
        # Дуже сильний пароль
        if len(pwd) >= min_len + 4 and is_unique:
            return "Дуже сильний"
        return "Сильний"

    met_count = sum([has_digit, has_upper, has_lower, has_spec])
    if met_count >= 2:
        return "Середній"

    return "Слабкий"


def run_task1():
    print(f"=== Завдання 1 | Студент: {STUDENT_NAME} ({GROUP_NAME}), Варіант {VARIANT_NUMBER} ===")

    pwd_list = passwords.copy()
    random.seed(42)
    dup_indices = random.sample(range(len(pwd_list)), 3)
    for idx in dup_indices:
        pwd_list.append(pwd_list[idx])

    print("\nРезультати аналізу паролів:")
    print(f"{'Пароль':<22} | {'Статус':<20}")
    print("-" * 45)

    for pwd in pwd_list:
        status = analyze_password(pwd, pwd_list)
        print(f"{pwd:<22} | {status:<20}")


if __name__ == "__main__":
    run_task1()