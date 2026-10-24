from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

# Maximum permissible payload size: 250 KB
MAX_BODY_BYTES = 250 * 1024


class LimitPayloadSizeMiddleware(BaseHTTPMiddleware):
    """Enforces a strict upper bound on the HTTP request body size.
    
    Protects against memory-exhaustion denial-of-service (DoS) attempts
    by validating Content-Length and actively limiting streamed bytes.
    """

    def __init__(self, app, max_upload_size: int = MAX_BODY_BYTES):
        super().__init__(app)
        self.max_upload_size = max_upload_size

    async def dispatch(self, request: Request, call_next):
        # Quick check: inspect Content-Length header if provided
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > self.max_upload_size:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": f"Payload exceeds maximum allowed limit of {self.max_upload_size} bytes."},
                    )
            except ValueError:
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid Content-Length header."},
                )

        # Stream-level protection for chunked transfers or omitted headers
        if request.method in ("POST", "PUT", "PATCH"):
            body = await request.body()
            if len(body) > self.max_upload_size:
                return JSONResponse(
                    status_code=413,
                    content={"detail": f"Payload exceeds maximum allowed limit of {self.max_upload_size} bytes."},
                )

        return await call_next(request)