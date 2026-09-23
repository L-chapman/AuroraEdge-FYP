"""Process-local authentication state, owned explicitly by one application.

This module has no singleton and reads no environment configuration. The HTTP
adapter supplies the current operator token on every session lookup so token
rotation keeps revoking sessions without restarting the application.
"""

from collections.abc import Callable
import hashlib
import hmac
import secrets
import threading
import time
from typing import TypedDict


class SessionRecord(TypedDict):
    csrf_token: str
    expires_at: float
    token_fingerprint: str


class AuthenticationState:
    """Own session and failed-login records and their synchronisation locks.

    Session expiry uses wall time (also returned to the browser), while the
    failed-login window uses monotonic time. Clock/token factories are injectable
    for isolated tests. No caller receives the mutable stored session record.
    Request parsing, origin/CSRF validation and HTTP errors belong to the adapter.
    """

    def __init__(
        self,
        *,
        session_ttl_seconds: int = 60 * 60 * 12,
        login_window_seconds: int = 300,
        max_failed_logins: int = 5,
        wall_clock: Callable[[], float] = time.time,
        monotonic_clock: Callable[[], float] = time.monotonic,
        token_factory: Callable[[int], str] = secrets.token_urlsafe,
    ):
        self._session_ttl_seconds = session_ttl_seconds
        self._login_window_seconds = login_window_seconds
        self._max_failed_logins = max_failed_logins
        self._wall_clock = wall_clock
        self._monotonic_clock = monotonic_clock
        self._token_factory = token_factory
        self._sessions: dict[str, SessionRecord] = {}
        self._session_lock = threading.Lock()
        self._failed_logins: dict[str, list[float]] = {}
        self._login_lock = threading.Lock()

    @staticmethod
    def _token_fingerprint(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create_session(self, configured_token: str) -> tuple[str, str]:
        """Create an expiring session bound to the supplied current token."""
        now = self._wall_clock()
        session_id = self._token_factory(32)
        csrf_token = self._token_factory(32)
        with self._session_lock:
            expired = [sid for sid, item in self._sessions.items() if item["expires_at"] <= now]
            for sid in expired:
                self._sessions.pop(sid, None)
            self._sessions[session_id] = {
                "csrf_token": csrf_token,
                "expires_at": now + self._session_ttl_seconds,
                "token_fingerprint": self._token_fingerprint(configured_token),
            }
        return session_id, csrf_token

    def get_session(self, session_id: str, configured_token: str) -> SessionRecord | None:
        """Return a snapshot; expired or token-mismatched sessions are removed."""
        if not session_id:
            return None
        now = self._wall_clock()
        with self._session_lock:
            session = self._sessions.get(session_id)
            if not session:
                return None
            if session["expires_at"] <= now or not hmac.compare_digest(
                session["token_fingerprint"], self._token_fingerprint(configured_token)
            ):
                self._sessions.pop(session_id, None)
                return None
            return session.copy()

    def revoke_session(self, session_id: str) -> None:
        """Remove a browser session; repeated or unknown revocations are safe."""
        with self._session_lock:
            self._sessions.pop(session_id, None)

    def login_allowed(self, client_key: str) -> bool:
        """Prune the client's failed attempts and check the existing window."""
        now = self._monotonic_clock()
        with self._login_lock:
            hits = [
                timestamp
                for timestamp in self._failed_logins.get(client_key, [])
                if now - timestamp < self._login_window_seconds
            ]
            self._failed_logins[client_key] = hits
            return len(hits) < self._max_failed_logins

    def record_login_failure(self, client_key: str) -> None:
        with self._login_lock:
            self._failed_logins.setdefault(client_key, []).append(self._monotonic_clock())

    def clear_login_failures(self, client_key: str) -> None:
        with self._login_lock:
            self._failed_logins.pop(client_key, None)
