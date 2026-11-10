"""Process-local activity counters for the dashboard."""
from contextlib import contextmanager
from threading import Lock


class Activity:
    def __init__(self):
        self._lock = Lock()
        self._count = 0

    @contextmanager
    def track(self):
        with self._lock:
            self._count += 1
        try:
            yield
        finally:
            with self._lock:
                self._count -= 1

    @property
    def processing(self):
        with self._lock:
            return self._count > 0


mail_work = Activity()
link_work = Activity()
chief_work = Activity()
