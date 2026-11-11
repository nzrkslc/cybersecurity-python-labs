# Лабораторна робота №3

**Тема:** Прикладні бібліотеки Python для побудови веб-застосунків  
**Варіант №13:** Реєстр ризиків хмарної конфігурації

---

## 1. Предметна область, одиниця вимірювання та обмеження

Сервіс реалізує облік знахідок аудиту хмарної конфігурації (навчальний Web API на базі **FastAPI**, **Pydantic v2** та **SQLite** без ORM).

* **Таблиця `categories`** (напрями перевірки хмарної конфігурації):
  * `id` — цілий первинний ключ (`id > 0`);
  * `name` — унікальна назва категорії (2–40 символів; початкові: `iam`, `storage`, `network`).
* **Таблиця `records`** (знахідки аудиту, зв’язок «один до багатьох» із `categories`, `ON DELETE RESTRICT`):
  * `id` — цілий первинний ключ (`id > 0`), генерується SQLite автоматично;
  * `code` — унікальний код знахідки (3–40 символів, формат початкових записів `V13-01`..`V13-08`);
  * `title` — назва знахідки аудиту (3–120 символів);
  * `category_id` — зовнішній ключ на `categories(id)` (`> 0`);
  * `value` — навчальна оцінка ризику (`float`, межі `0.0–10.0` включно, без `NaN`/`Infinity`);
  * `status` — стан опрацювання (`new`, `in_progress`, `done`).
* **Одиниця вимірювання (`unit`):** `score`.
* **Поріг підвищеної уваги:** `7.0`.

---

## 2. Структура каталогу `labs/lab03/`

```text
labs/lab03/
├── __init__.py
├── main.py              # FastAPI-застосунок, lifespan-ініціалізація, /ping, /student
├── database.py          # Підключення до SQLite (PRAGMA foreign_keys = ON) та виконання schema.sql
├── schema.sql           # Готова схема таблиць categories і records (Варіанти 13–15)
├── repository.py        # Параметризовані SQL-запити (JOIN, фільтри, пагінація, транзакції)
├── schemas.py           # Pydantic-моделі запитів, відповідей і перевірки seed.json
├── config.py            # Параметри варіанта, одиниця вимірювання, поріг і обмеження
├── seed.py              # Валідація та початкове заповнення бази з JSON в одній транзакції
├── routers/
│   ├── __init__.py      # Перетворення доменних і SQLite-помилок на HTTPException
│   ├── categories.py    # Маршрути /categories
│   └── records.py       # Маршрути /records та /records/bulk
├── data/
│   ├── seed.json        # Початкові навчальні дані Варіанта 13 (3 категорії, 8 записів)
│   └── lab3.sqlite3     # Файл бази SQLite (створюється локально, виключений із Git)
└── README.md            # Документація, інструкції запуску та приклади запитів
```

---

## 3. Встановлення залежностей

Усі команди виконуються з кореня репозиторію `cybersecurity-python-labs/` в активованому віртуальному середовищі (Python 3.10+):

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

## 4. Ініціалізація бази, початкове заповнення та запуск API

1. **(Необов’язково, виконується автоматично під час `seed` або запуску API)** Створити таблиці SQLite за готовою схемою:
   ```powershell
   python -m labs.lab03.database
   ```
2. **Заповнити порожню базу навчальними даними Варіанта 13** (3 категорії та 8 записів в одній транзакції):
   ```powershell
   python -m labs.lab03.seed
   ```
   Повторний запуск виведе інформаційне повідомлення та не змінить наявні дані й не створить дублікатів.
3. **Запустити вебсервер FastAPI:**
   ```powershell
   uvicorn labs.lab03.main:app --reload --host 127.0.0.1 --port 8000
   ```
4. **Відкрити автоматичну документацію:**
   * Swagger UI: `http://127.0.0.1:8000/docs`
   * OpenAPI-схема: `http://127.0.0.1:8000/openapi.json`

---

## 5. Приклади основних запитів

Команди нижче наведено для `curl` (у Windows `curl.exe` або через інтерактивний Swagger UI `/docs`):

### Перевірка сервісу, даних студента та категорій

```bash
curl -i "http://127.0.0.1:8000/ping"
curl -i "http://127.0.0.1:8000/student"
curl -i "http://127.0.0.1:8000/categories"
```

### Створення та видалення категорії

```bash
curl -i -X POST "http://127.0.0.1:8000/categories" \
  -H "Content-Type: application/json" \
  -d '{"name":"serverless"}'

curl -i -X DELETE "http://127.0.0.1:8000/categories/4"
```

### Отримання записів із фільтрацією та пагінацією

```bash
curl -i "http://127.0.0.1:8000/records?category_id=1&status=new&limit=5&offset=0"
curl -i "http://127.0.0.1:8000/records?min_value=7.0&limit=10&offset=0"
curl -i "http://127.0.0.1:8000/records/1"
```

### Повний цикл CRUD для запису

```bash
# Створення (201 Created)
curl -i -X POST "http://127.0.0.1:8000/records" \
  -H "Content-Type: application/json" \
  -d '{"code":"V13-TEST","title":"Тестова знахідка аудиту","category_id":1,"value":7.5,"status":"new"}'

# Повне оновлення змінюваних полів (200 OK)
curl -i -X PUT "http://127.0.0.1:8000/records/9" \
  -H "Content-Type: application/json" \
  -d '{"code":"V13-TEST-UPD","title":"Оновлена знахідка аудиту","category_id":3,"value":8.5,"status":"done"}'

# Видалення (204 No Content)
curl -i -X DELETE "http://127.0.0.1:8000/records/9"
```

### Пакетне створення та перевірка атомарності транзакції

```bash
# Успішний пакет (201 Created)
curl -i -X POST "http://127.0.0.1:8000/records/bulk" \
  -H "Content-Type: application/json" \
  -d '[{"code":"V13-09","title":"Пакетна знахідка 09","category_id":1,"value":6.0,"status":"new"},{"code":"V13-10","title":"Пакетна знахідка 10","category_id":3,"value":8.2,"status":"in_progress"}]'

# Відкат усього пакета при конфлікті унікальності code (409 Conflict; V13-ROLLBACK не зберігається)
curl -i -X POST "http://127.0.0.1:8000/records/bulk" \
  -H "Content-Type: application/json" \
  -d '[{"code":"V13-ROLLBACK","title":"Перший елемент","category_id":1,"value":4.0,"status":"new"},{"code":"V13-01","title":"Дублікат коду","category_id":2,"value":5.0,"status":"new"}]'
```

---

## 6. Перевірка стилю коду (Ruff)

```powershell
ruff check labs/lab03
ruff format --check labs/lab03
ruff check .
ruff format --check .
```
