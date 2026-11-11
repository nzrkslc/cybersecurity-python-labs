"""Допоміжні засоби для маршрутизаторів API."""

import logging
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager

from fastapi import HTTPException, status

from labs.lab03.repository import ConflictError, NotFoundError

logger = logging.getLogger(__name__)


@contextmanager
def repository_error_handler() -> Iterator[None]:
    """Перетворити доменні та SQLite-винятки на відповідні HTTPException."""
    try:
        yield
    except NotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except ConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except sqlite3.Error as exc:
        logger.exception("Неочікувана помилка SQLite у шарі API")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Внутрішня помилка роботи з базою даних.",
        ) from exc
