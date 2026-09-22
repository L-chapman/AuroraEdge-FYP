"""Small, shared request boundaries for both the current and legacy APIs."""

import hmac

from fastapi import HTTPException, Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send


MAX_REQUEST_BYTES = 64 * 1024


def constant_time_equal(supplied: str, expected: str) -> bool:
    """Compare UTF-8 text safely, including untrusted non-ASCII credentials."""
    try:
        return hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))
    except UnicodeError:
        return False


async def json_object(request: Request) -> dict:
    """Reject malformed/non-object JSON before a route uses dictionary methods."""
    try:
        body = await request.json()
    except (ValueError, UnicodeError, RecursionError):
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="The JSON body must be an object")
    return body


class RequestSizeLimitMiddleware:
    """Bound request bodies before FastAPI parses them, even without a length.

    There are no upload endpoints. The largest supported operator request is
    comfortably below 64 KiB. Buffering this bounded body also keeps an oversized
    JSON value out of validation responses and avoids trusting Content-Length.
    """

    def __init__(self, app: ASGIApp, max_bytes: int = MAX_REQUEST_BYTES):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH", "DELETE"}:
            await self.app(scope, receive, send)
            return

        async def reject(status: int, detail: str):
            await JSONResponse({"detail": detail}, status_code=status)(scope, receive, send)

        for key, value in scope.get("headers", []):
            if key.lower() == b"content-length":
                try:
                    length = int(value)
                except ValueError:
                    await reject(400, "Invalid request length")
                    return
                if length < 0:
                    await reject(400, "Invalid request length")
                    return
                if length > self.max_bytes:
                    await reject(413, "Request body is too large (maximum 64 KiB)")
                    return

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > self.max_bytes:
                await reject(413, "Request body is too large (maximum 64 KiB)")
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break

        replayed = False

        async def bounded_receive():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, bounded_receive, send)
