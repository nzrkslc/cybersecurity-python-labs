"""Конфігурація та обмеження предметної області для Лабораторної роботи №3 (Варіант 13)."""

VARIANT_NUMBER = 13

APP_TITLE = "Реєстр ризиків хмарної конфігурації"
APP_VERSION = "1.0.0"
VALUE_UNIT = "score"
RISK_THRESHOLD = 7.0

VALUE_MIN = 0.0
VALUE_MAX = 10.0

ALLOWED_STATUSES = ("new", "in_progress", "done")

CATEGORY_NAME_MIN_LEN = 2
CATEGORY_NAME_MAX_LEN = 40

RECORD_CODE_MIN_LEN = 3
RECORD_CODE_MAX_LEN = 40

RECORD_TITLE_MIN_LEN = 3
RECORD_TITLE_MAX_LEN = 120

QUERY_MIN_LEN = 1
QUERY_MAX_LEN = 120

DEFAULT_LIMIT = 20
MAX_LIMIT = 100

BULK_MIN_ITEMS = 1
BULK_MAX_ITEMS = 100

APP_DESCRIPTION = (
    "Навчальний Web API для обліку знахідок аудиту хмарної конфігурації "
    "(Варіант 13). Категорія визначає напрям перевірки (`iam`, `storage`, `network`), "
    f"поле `value` задає навчальну оцінку ризику в діапазоні від {VALUE_MIN} до {VALUE_MAX} "
    f"(одиниця вимірювання: `{VALUE_UNIT}`, поріг підвищеної уваги: `{RISK_THRESHOLD}`), "
    "а `status` відображає стан опрацювання знахідки (`new`, `in_progress`, `done`)."
)
