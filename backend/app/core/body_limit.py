"""
(6 Nov audit) One size limit for EVERY request body, checked before the body is read.

File uploads already stop at MAX_UPLOAD_MB, but a JSON / form request was read into memory whole before its fields
were checked, so a single huge request could fill the server's memory. Limit: 2 x MAX_UPLOAD_MB + 2 MB (the largest
real request is a scan with a file and a reference file). Requests that do not announce their size (chunked) are
counted while they arrive and stopped at the same limit.
"""
import json

_TOO_LARGE = json.dumps({"error": {"code": "REQUEST_TOO_LARGE",
                                   "message": "The request is too large."}}).encode()


class _Overflow(Exception):
    pass


class BodySizeLimit:
    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def _reject(self, send):
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(_TOO_LARGE)).encode())]})
        await send({"type": "http.response.body", "body": _TOO_LARGE})

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        length = dict(scope.get("headers") or []).get(b"content-length")
        if length is not None:
            try:
                if int(length) > self.max_bytes:
                    return await self._reject(send)
            except ValueError:
                return await self._reject(send)
        seen, started, overflowed = 0, False, False

        async def counted_receive():
            nonlocal seen, overflowed
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self.max_bytes:
                    overflowed = True
                    raise _Overflow()
            return message

        async def tracked_send(message):
            nonlocal started
            if overflowed:                     # the app caught the stop and answers with its own error: send 413
                if message["type"] == "http.response.start" and not started:
                    started = True
                    await self._reject(send)
                return
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, counted_receive, tracked_send)
        except _Overflow:
            if not started:
                started = True
                await self._reject(send)
