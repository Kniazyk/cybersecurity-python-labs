# Лабораторна робота №4. NVD API та автоматизоване тестування

Консольна утиліта шукає запис про вразливість за ідентифікатором CVE в NVD
(CVE API 2.0) або читає локальну відповідь із файла, застосовує правило
варіанта й виводить JSON-звіт.

**Варіант:** 10 (значення береться з `shared.student.VARIANT_NUMBER`).

## Правило варіанта 10

Запис відбирається для ручного огляду (`decision = "review"`), якщо в **одній і
тій самій** вибраній оцінці CVSS v3.1:

- `baseScore >= 6.0` і
- `cvssData.privilegesRequired == "LOW"`.

`privilegesRequired` — привілеї, потрібні зловмиснику до атаки (`NONE`, `LOW`,
`HIGH`). Це не те саме, що `userInteraction`. Оцінка CVSS описує технічну
серйозність, а не ризик для конкретної системи.

Вибір оцінки: аналізується лише `metrics.cvssMetricV31`; береться перший
елемент із `type="Primary"`, а якщо його немає — перший елемент списку.

## Встановлення

Усі команди виконуйте з кореня репозиторію, у віртуальному середовищі з
Python 3.12+:

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Запуск

Локальний режим (без мережі, синтетичний запис `CVE-2099-10001`):

```bash
python -m labs.lab04.main --cve CVE-2099-10001 --input labs/lab04/data/nvd_sample.json
```

Мережевий режим (один ручний запит; не запускайте пакетно чи в циклі й
перегляньте правила використання NVD API):

```bash
python -m labs.lab04.main --cve CVE-2021-44228
```

Ключ NVD API необов'язковий. Якщо змінна середовища `NVD_API_KEY` непорожня,
клієнт передає її в заголовку `apiKey` (не в URL). Не зберігайте ключ у
файлах проєкту й не додавайте його до Git.

Аргументи: `--cve` (обов'язковий, формат `CVE-[0-9]{4}-[0-9]{4,}`, регістр
має значення), `--input` (шлях до локального UTF-8 JSON; мережевий запит не
виконується).

Коди завершення: `0` — звіт сформовано (зокрема `not_found`,
`insufficient_data`), `1` — помилка отримання, читання чи перевірки даних
(повідомлення в stderr), `2` — неправильні аргументи або номер варіанта.

## Формат звіту

У stdout виводиться один JSON-об'єкт:

| Ключ | Значення |
|---|---|
| `cve_id` | запитаний ідентифікатор |
| `variant` | номер варіанта |
| `description` | перший непорожній англійський опис або `null` |
| `vuln_status` | статус NVD або `null` |
| `cvss_version` | `"3.1"` або `null` |
| `score` | вибрана оцінка або `null` |
| `score_source` | джерело вибраної оцінки або `null` |
| `vector` | вектор вибраної оцінки або `null` |
| `rule` | `{"threshold": 6.0, "field": "privilegesRequired", "expected": "LOW"}` |
| `observed` | значення `privilegesRequired` у вибраній оцінці або `null` |
| `decision` | `not_found`, `rejected`, `insufficient_data`, `review` або `other` |

Порядок станів: запис не знайдено → `not_found`; статус `Rejected` →
`rejected`; немає статусу, оцінки v3.1 або поля `privilegesRequired` →
`insufficient_data`; `score >= 6.0` і `privilegesRequired == "LOW"` →
`review`; інакше → `other`. Стани `other` та `insufficient_data` не означають,
що вразливість безпечна.

Для синтетичного файла очікується `other` (оцінка 9.8, але
`privilegesRequired = "NONE"`).

## Структура

```
labs/lab04/
├── main.py        # аргументи, виклик функцій, повідомлення, коди завершення
├── api_client.py  # build_headers(), fetch_response(): один GET-запит
├── analysis.py    # extract_record(), build_report(): перевірка й правило
├── data/nvd_sample.json
└── tests/         # test_analysis.py, test_api_client.py, test_main.py
```

## Перевірка

```bash
python -m pytest labs/lab04/tests -q
ruff check labs/lab04
ruff format --check labs/lab04
```

Тести не звертаються до мережі: `tests/conftest.py` автоматично блокує
`requests.sessions.Session.request` і прибирає `NVD_API_KEY` перед кожним
тестом. Результат живого запиту до NVD в автоматичні тести не закріплюється.
