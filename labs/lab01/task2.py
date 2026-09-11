import os
import sys

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../../")
    )
)

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

users = {
    "iot_specialist": {
        "role": "iot_security",
        "clearance": 3,
        "department": "IoT",
        "active": True,
    },
    "mobile_analyst": {
        "role": "mobile_security",
        "clearance": 3,
        "department": "Mobile",
        "active": True,
    },
    "web_developer": {
        "role": "web_developer",
        "clearance": 2,
        "department": "Web",
        "active": True,
    },
    "api_consumer": {
        "role": "api_user",
        "clearance": 2,
        "department": "Integration",
        "active": True,
    },
    "demo_account": {
        "role": "demonstration",
        "clearance": 1,
        "department": "Demo",
        "active": False,
    },
}

resources = [
    ("iot_firmware", 3),
    ("mobile_policies", 3),
    ("web_applications", 2),
    ("api_gateway", 2),
    ("device_certificates", 3),
    ("app_store", 1),
    ("vulnerability_database", 3),
    ("device_management", 3),
    ("integration_docs", 2),
    ("demo_content", 1),
]

security_levels = ("Consumer", "Business", "Enterprise", "Critical Systems")
blocked_users = {"demo_account", "compromised_device", "malicious_app"}


def check_access(user_id: str, resource_name: str, resource_level: int) -> str:

    if user_id not in users: # Перевірка доступу користувача
        return "DENY (User not found)"

    if user_id in blocked_users:
        return "DENY (User is blocked)"

    user_info = users[user_id]

    if not user_info.get("active", False):
        return "DENY (Account inactive)"

    user_clearance = user_info.get("clearance", 0)

    if user_clearance >= resource_level:
        return "ALLOW"

    return "DENY (Insufficient clearance)"


def run_task2():

    print(
        f"=== Завдання 2 | Студент: {STUDENT_NAME} ({GROUP_NAME}), Варіант {VARIANT_NUMBER} ==="
    )

    print("\n--- Список ресурсів системи ---")
    for res_name, res_level in resources:
        level_name = security_levels[res_level - 1]
        print(f"Ресурс: {res_name:<25} | Рівень: {level_name}")

    print("\n--- Результати перевірки доступу ---")

    test_user_ids = list(users.keys()) + ["guest_user"]   # Перевірка всіх користувачів

    for u_id in test_user_ids:
        for res_name, res_level in resources:
            result = check_access(u_id, res_name, res_level)
            print(f"user=[{u_id}] resource=[{res_name}] -> {result}")


if __name__ == "__main__":
    run_task2()