import os
import sys

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../../")
    )
)

from labs.lab01.task1 import run_task1
from labs.lab01.task2 import run_task2
from labs.lab01.task3 import run_task3
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


def main():
    print("=" * 60)
    print(f"ЛАБОРАТОРНА РОБОТА №1 | Варіант {VARIANT_NUMBER}")
    print(f"Виконала: {STUDENT_NAME}, Група {GROUP_NAME}")
    print("=" * 60 + "\n")

    print("\n>>> ЗАПУСК ЗАВДАННЯ 1 <<<\n")
    run_task1()

    print("\n" + "=" * 60)
    print("\n>>> ЗАПУСК ЗАВДАННЯ 2 <<<\n")
    run_task2()

    print("\n" + "=" * 60)
    print("\n>>> ЗАПУСК ЗАВДАННЯ 3 <<<\n")
    run_task3()

    print("\n" + "=" * 60)
    print("Лабораторну роботу №1 успішно завершено!")


if __name__ == "__main__":
    main()