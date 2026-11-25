# Лабораторна робота №4

**Тема:** Інтеграція із зовнішніми Web API та автоматизоване тестування Python-коду  
**Студент:** Кисилиця Назар, група КБ-208  
**Варіант №13:** Низький вплив на цілісність (`score >= 6.0` та `cvssData["integrityImpact"] == "LOW"`)

---

## 1. Структура каталогу `labs/lab04/`

```text
labs/lab04/
├── __init__.py
├── main.py              # CLI-інтерфейс, перевірка варіанта та аргументів, обробка помилок
├── api_client.py        # Формування заголовків (apiKey) і GET-запит до NVD CVE API 2.0
├── analysis.py          # Валідація структури відповіді, вибір CVSS v3.1 і правило варіанта
├── data/
│   └── nvd_sample.json  # Синтетична відповідь NVD (CVE-2099-10001) для локального режиму
├── tests/
│   ├── __init__.py
│   ├── conftest.py      # Ізоляція середовища: заборона мережевих запитів і видалення NVD_API_KEY
│   ├── test_analysis.py # Модульні тести перевірки контракту та правила варіанта 13
│   ├── test_api_client.py # Тести HTTP-клієнта з підміною requests.get
│   └── test_main.py     # Інтеграційні тести CLI (локальний і API-режими, коди завершення)
└── README.md            # Інструкція з встановлення, запуску, формату звіту та перевірки
```

---

## 2. Встановлення залежностей

Усі команди виконуються з кореня репозиторію `cybersecurity-python-labs/` в активованому віртуальному середовищі з Python 3.12+:

```powershell
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

```bash
# Linux / macOS / Git Bash
source .venv/bin/activate
pip install -r requirements.txt
```

---

## 3. Правило варіанта №13 та формат звіту

Для відбору записів до ручного огляду використовується метрика **CVSS v3.1** із `metrics.cvssMetricV31` (пріоритет має перший елемент із `type="Primary"`, за його відсутності — перший елемент списку):

* **Поріг (`threshold`):** `6.0`
* **Поле (`field`):** `integrityImpact` (допустимі значення: `NONE`, `LOW`, `HIGH`)
* **Очікуване значення (`expected`):** `LOW`
* **Умова `review`:** `score >= 6.0` і водночас `cvssData["integrityImpact"] == "LOW"` у тій самій вибраній оцінці.

### Формат вихідного JSON-звіту

Успішний запуск виводить у `stdout` один JSON-об'єкт з такими ключами:

* `cve_id` — запитаний ідентифікатор CVE;
* `variant` — номер варіанта (`13`);
* `description` — перший непорожній англомовний опис або `null`;
* `vuln_status` — статус запису NVD або `null`;
* `cvss_version` — `"3.1"` або `null`;
* `score` — базова оцінка CVSS v3.1 або `null`;
* `score_source` — джерело вибраної оцінки або `null`;
* `vector` — вектор CVSS v3.1 або `null`;
* `rule` — об'єкт `{"threshold": 6.0, "field": "integrityImpact", "expected": "LOW"}`;
* `observed` — фактичне значення `integrityImpact` у вибраній оцінці або `null`;
* `decision` — підсумковий стан у порядку пріоритету: `not_found`, `rejected`, `insufficient_data`, `review`, `other`.

### Коди завершення CLI

* `0` — дані успішно опрацьовано та сформовано JSON-звіт (зокрема для `not_found`, `rejected` або `insufficient_data`);
* `1` — помилка мережі, таймауту, HTTP-статусу, читання файла, розбору JSON або порушення структури даних (повідомлення виводиться у `stderr` без трасування стека й секретів);
* `2` — некоректні аргументи командного рядка або некоректний `VARIANT_NUMBER`.

---

## 4. Команди запуску

### Локальний режим (без мережі)

```powershell
python -m labs.lab04.main --cve CVE-2099-10001 --input labs/lab04/data/nvd_sample.json
```

### Режим звернення до NVD CVE API 2.0

Без ключа API:

```powershell
python -m labs.lab04.main --cve CVE-2021-44228
```

За наявності ключа API у змінній середовища `NVD_API_KEY` він передається в HTTP-заголовку `apiKey` (не у URL):

```powershell
$env:NVD_API_KEY = "your-api-key"
python -m labs.lab04.main --cve CVE-2021-44228
```

---

## 5. Перевірка тестів та стилю коду

Автоматичні тести (`pytest`) працюють повністю офлайн із забороною реальних мережевих запитів у `tests/conftest.py`:

```powershell
python -m pytest labs/lab04/tests -q
ruff check labs/lab04
ruff format --check labs/lab04
```
