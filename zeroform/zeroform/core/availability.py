"""
Operating Hours / Availability Engine
========================================

Feeds the Virtual SOC / Control Room's "is the desk staffed right
now?" indicator. Every value here is user-supplied through the CLI
(``zeroform hours``), the REST API (``/api/hours``) or the GUI's
Operating Hours panel -- nothing is hard-coded: the user enters, per
weekday, one or more open/close windows (or marks the day fully open
"24h" or fully closed), an optional list of date-specific exceptions
(holidays / special hours / emergency closures), and a timezone
label. The engine then answers, for any point in time:

  * is the desk currently open, and if so when does the current
    window close and how long is left,
  * if it is currently closed, when does the next window open and
    how long is left until then.

This module has no dependency on the rest of the security-compiler
domain model on purpose -- it is a small, general-purpose scheduling
utility reused by the SOC dashboard, on-call rotations and any future
"is X available right now" panel.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, date, time as dtime, timedelta
from typing import Any, Dict, List, Optional

WEEKDAY_NAMES = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]


def _parse_hhmm(value: str) -> dtime:
    hh, mm = value.strip().split(":")
    return dtime(hour=int(hh), minute=int(mm))


def _fmt_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    if minutes or hours or days:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")
    return " ".join(parts)


@dataclass
class OperatingWindow:
    open_time: str = "09:00"     # "HH:MM", ignored if is_24h or closed
    close_time: str = "17:00"    # "HH:MM"; if <= open_time, window spans midnight

    def to_dict(self) -> Dict[str, str]:
        return {"open_time": self.open_time, "close_time": self.close_time}


@dataclass
class DaySchedule:
    weekday: int                          # 0 = Monday ... 6 = Sunday
    closed: bool = False
    is_24h: bool = False
    windows: List[OperatingWindow] = field(default_factory=lambda: [OperatingWindow()])

    def to_dict(self) -> Dict[str, Any]:
        return {"weekday": self.weekday, "closed": self.closed, "is_24h": self.is_24h,
                "windows": [w.to_dict() for w in self.windows]}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "DaySchedule":
        return cls(weekday=int(d["weekday"]), closed=bool(d.get("closed", False)),
                    is_24h=bool(d.get("is_24h", False)),
                    windows=[OperatingWindow(**w) for w in d.get("windows", [])] or [OperatingWindow()])


@dataclass
class ScheduleException:
    """A single-date override, e.g. a holiday or an emergency closure."""
    on_date: str                          # "YYYY-MM-DD"
    closed: bool = True
    is_24h: bool = False
    windows: List[OperatingWindow] = field(default_factory=list)
    label: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"on_date": self.on_date, "closed": self.closed, "is_24h": self.is_24h,
                "windows": [w.to_dict() for w in self.windows], "label": self.label}

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ScheduleException":
        return cls(on_date=d["on_date"], closed=bool(d.get("closed", True)),
                    is_24h=bool(d.get("is_24h", False)),
                    windows=[OperatingWindow(**w) for w in d.get("windows", [])], label=d.get("label", ""))


@dataclass
class OperatingHoursSchedule:
    """The full, user-entered weekly schedule plus date exceptions."""
    timezone_label: str = "UTC"
    days: Dict[int, DaySchedule] = field(default_factory=dict)
    exceptions: List[ScheduleException] = field(default_factory=list)

    def __post_init__(self) -> None:
        for wd in range(7):
            self.days.setdefault(wd, DaySchedule(weekday=wd))

    def set_day(self, weekday: int, closed: bool = False, is_24h: bool = False,
                windows: Optional[List[OperatingWindow]] = None) -> None:
        self.days[weekday] = DaySchedule(weekday=weekday, closed=closed, is_24h=is_24h,
                                          windows=windows or [OperatingWindow()])

    def add_exception(self, exc: ScheduleException) -> None:
        self.exceptions = [e for e in self.exceptions if e.on_date != exc.on_date] + [exc]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timezone_label": self.timezone_label,
            "days": {str(k): v.to_dict() for k, v in self.days.items()},
            "exceptions": [e.to_dict() for e in self.exceptions],
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "OperatingHoursSchedule":
        sched = cls(timezone_label=d.get("timezone_label", "UTC"))
        for k, v in d.get("days", {}).items():
            sched.days[int(k)] = DaySchedule.from_dict(v)
        sched.exceptions = [ScheduleException.from_dict(e) for e in d.get("exceptions", [])]
        return sched


class OperatingHoursEngine:
    """Pure computation over a user-supplied :class:`OperatingHoursSchedule`.
    All 'now' values are supplied by the caller (default: real wall
    clock) so the engine stays trivially unit-testable and reusable
    from the CLI, API and GUI without duplicating logic in JavaScript."""

    def __init__(self, schedule: OperatingHoursSchedule):
        self.schedule = schedule

    def _day_windows_as_datetimes(self, day: date, day_schedule: DaySchedule,
                                   exception: Optional[ScheduleException]) -> List[Dict[str, datetime]]:
        effective = exception if exception is not None else day_schedule
        if effective.closed:
            return []
        if effective.is_24h:
            return [{"start": datetime.combine(day, dtime(0, 0)),
                      "end": datetime.combine(day, dtime(0, 0)) + timedelta(days=1)}]
        windows = effective.windows if isinstance(effective, (DaySchedule, ScheduleException)) else []
        out = []
        for w in windows:
            start = datetime.combine(day, _parse_hhmm(w.open_time))
            end_time = _parse_hhmm(w.close_time)
            end = datetime.combine(day, end_time)
            if end_time <= _parse_hhmm(w.open_time):
                end += timedelta(days=1)   # overnight window
            out.append({"start": start, "end": end})
        return out

    def _exception_for(self, day: date) -> Optional[ScheduleException]:
        key = day.isoformat()
        for e in self.schedule.exceptions:
            if e.on_date == key:
                return e
        return None

    def _all_windows_around(self, now: datetime, horizon_days: int = 15) -> List[Dict[str, datetime]]:
        """Collects windows starting one day before `now` (to catch an
        overnight window still open from yesterday) through
        `horizon_days` ahead (to survive a run of holiday/closed
        exceptions before the next real opening)."""
        windows: List[Dict[str, datetime]] = []
        for offset in range(-1, horizon_days + 1):
            day = (now + timedelta(days=offset)).date()
            day_schedule = self.schedule.days[day.weekday()]
            exception = self._exception_for(day)
            windows.extend(self._day_windows_as_datetimes(day, day_schedule, exception))
        return sorted(windows, key=lambda w: w["start"])

    def status(self, now: Optional[datetime] = None) -> Dict[str, Any]:
        now = now or datetime.now()
        windows = self._all_windows_around(now)

        for w in windows:
            if w["start"] <= now < w["end"]:
                remaining = (w["end"] - now).total_seconds()
                return {
                    "is_open": True,
                    "timezone_label": self.schedule.timezone_label,
                    "current_window_opened_at": w["start"].isoformat(),
                    "current_window_closes_at": w["end"].isoformat(),
                    "seconds_until_close": remaining,
                    "human_time_until_close": _fmt_duration(remaining),
                    "checked_at": now.isoformat(),
                }

        future = [w for w in windows if w["start"] > now]
        if not future:
            return {
                "is_open": False,
                "timezone_label": self.schedule.timezone_label,
                "next_open_at": None,
                "seconds_until_open": None,
                "human_time_until_open": None,
                "note": "no upcoming open window found in the schedule horizon",
                "checked_at": now.isoformat(),
            }
        nxt = future[0]
        remaining = (nxt["start"] - now).total_seconds()
        return {
            "is_open": False,
            "timezone_label": self.schedule.timezone_label,
            "next_open_at": nxt["start"].isoformat(),
            "next_close_at": nxt["end"].isoformat(),
            "seconds_until_open": remaining,
            "human_time_until_open": _fmt_duration(remaining),
            "checked_at": now.isoformat(),
        }

    def weekly_summary(self) -> List[Dict[str, Any]]:
        out = []
        for wd in range(7):
            d = self.schedule.days[wd]
            out.append({
                "weekday": WEEKDAY_NAMES[wd],
                "closed": d.closed,
                "is_24h": d.is_24h,
                "windows": [w.to_dict() for w in d.windows] if not (d.closed or d.is_24h) else [],
            })
        return out
