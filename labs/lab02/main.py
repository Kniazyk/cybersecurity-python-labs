"""Точка входу лабораторної роботи №2: команди demo та analyze."""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from labs.lab02.task1 import Admin, User, UserAccount
from labs.lab02.task2 import configure_logging
from labs.lab02.task2 import run_analyze as task2_run_analyze


def run_demo() -> None:
    """Демонстрація роботи класів Завдання 1 (ООП)."""
    print("=== 1. Створення користувача та облікового запису ===")
    user = User("alice", "alice_01@example.com", "user", "S3cret!pass")
    account = UserAccount(user)
    print(user)

    print("\n=== 2. Успішний вхід ===")
    ok = account.login("alice", "S3cret!pass", "10.0.0.5")
    print(f"Вхід виконано: {ok}, автентифікація активна: {account.is_authenticated()}")

    print("\n=== 3. Невдалий вхід (неправильний пароль) ===")
    fresh_account = UserAccount(User("bob", "bob_1@example.com", "user", "Correct1!"))
    fail = fresh_account.login("bob", "wrong-password", "10.0.0.9")
    print(
        f"Вхід виконано: {fail}, "
        f"автентифікація активна: {fresh_account.is_authenticated()}"
    )

    print("\n=== 4. Зміна email із перевіркою ===")
    print(f"Email до зміни: {user.email}")
    user.email = "alice_new@example.com"
    print(f"Email після зміни: {user.email}")
    try:
        user.email = "no-at-sign-example.com"
    except ValueError as exc:
        print(f"Спроба встановити некоректний email відхилена: {exc}")

    print("\n=== 5. Права адміністратора ===")
    admin = Admin("root", "root_admin@example.com", "AdminPass!1")
    admin.grant_permission("manage_users")
    admin.grant_permission("view_reports")
    print(admin)
    print(f"Має право 'manage_users': {admin.has_permission('manage_users')}")
    admin.revoke_permission("view_reports")
    print(f"Після відкликання 'view_reports': {admin}")

    print("\n=== 6. Завершення сесії за таймаутом ===")
    timeout_demo = UserAccount(
        User("carol", "carol_1@example.com", "user", "Timeout1!")
    )
    timeout_demo.login("carol", "Timeout1!", "10.0.0.20")
    print(f"Одразу після входу: {timeout_demo.is_authenticated()}")
    print("Очікуємо 2 секунди та штучно ставимо короткий таймаут для демонстрації...")
    time.sleep(2)
    session_is_active_after_2s = timeout_demo.session.is_active(1)
    print(f"is_active(timeout_sec=1) через 2 секунди: {session_is_active_after_2s}")

    print("\n=== 7. Logout ===")
    account.logout()
    print(f"Автентифікація після logout: {account.is_authenticated()}")

    print("\n=== 8. Записи AuditLog ===")
    account.audit_log.show_all()


def run_analyze(args: argparse.Namespace) -> int:
    """Викликає повну логіку аналізу сертифікатів із task2.py."""
    configure_logging()
    try:
        task2_run_analyze(
            certs_data=args.certs_data,
            days_warning=args.days_warning,
            output_report=args.output_report,
            fmt=args.format,
        )
    except (FileNotFoundError, ValueError, KeyError, TypeError) as exc:
        print(f"[ERROR] {exc}")
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m labs.lab02.main",
        description="Лабораторна робота №2: демонстрація ООП та монітор SSL/TLS сертифікатів.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("demo", help="Демонстрація класів Завдання 1")

    analyze_parser = subparsers.add_parser(
        "analyze", help="Аналіз SSL/TLS сертифікатів (Завдання 2)"
    )
    analyze_parser.add_argument("--certs-data", required=True, type=Path)
    analyze_parser.add_argument("--days-warning", type=int, default=30)
    analyze_parser.add_argument("--output-report", type=Path, default=None)
    analyze_parser.add_argument("--format", choices=["json", "csv"], default="json")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "demo":
        run_demo()
    elif args.command == "analyze":
        run_analyze(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
