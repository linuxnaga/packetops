"""Structured JSON logging with request / analysis correlation IDs.

Payload bytes, cookies, Authorization headers and tokens are never passed to
the logger by application code; ``RedactingFilter`` additionally masks bearer
tokens if one ever appears in a message.
"""

from __future__ import annotations

import contextvars
import json
import logging
import re
import sys
import time

request_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("request_id", default=None)
tenant_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("tenant_id", default=None)
job_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("job_id", default=None)

_TOKEN_RE = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+")
_RESERVED = set(vars(logging.makeLogRecord({})).keys()) | {"message", "asctime"}


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str) and "earer" in record.msg:
            record.msg = _TOKEN_RE.sub(r"\1[REDACTED]", record.msg)
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, var in (("request_id", request_id_var), ("tenant_id", tenant_id_var), ("job_id", job_id_var)):
            v = var.get()
            if v:
                out[key] = v
        for k, v in record.__dict__.items():
            if k not in _RESERVED and not k.startswith("_"):
                out[k] = v if isinstance(v, (str, int, float, bool, type(None))) else str(v)
        if record.exc_info:
            out["exc"] = self.formatException(record.exc_info)
        return json.dumps(out, default=str)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RedactingFilter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    for noisy in ("pymongo", "botocore", "urllib3", "s3transfer"):
        logging.getLogger(noisy).setLevel("WARNING")
