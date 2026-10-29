"""Calcul du statut d'une branche à partir de sa date de fin de support."""

import calendar
import datetime as dt


def add_months(day: dt.date, months: int) -> dt.date:
    month_index = day.month - 1 + months
    year, month = day.year + month_index // 12, month_index % 12 + 1
    return dt.date(year, month, min(day.day, calendar.monthrange(year, month)[1]))


def compute_status(trigger_date: str | None, declared_eol: bool, today: dt.date, eol_soon_months: int) -> str:
    if trigger_date:
        end = dt.date.fromisoformat(trigger_date)
        if end <= today:
            return "eol"
        if end <= add_months(today, eol_soon_months):
            return "eol_soon"
        return "active"
    return "eol" if declared_eol else "active"
