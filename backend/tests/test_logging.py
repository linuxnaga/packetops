import json
import logging

from app.core.logging import JsonFormatter, RedactingFilter, configure_logging


def _render(msg, *args):
    rec = logging.LogRecord("uvicorn.access", logging.INFO, __file__, 1, msg, args, None)
    RedactingFilter().filter(rec)
    return json.loads(JsonFormatter().format(rec))["msg"]


def test_access_log_query_token_is_redacted():
    # uvicorn's access log passes the URL as an argument, not in the format string.
    out = _render('%s - "%s %s HTTP/%s" %d', "127.0.0.1:5", "GET", "/api/v1/captures/cap_x/events?access_token=eyJhbGci.eyJzdWIi.sig", "1.1", 200)
    assert "eyJ" not in out
    assert "access_token=[REDACTED]" in out


def test_bearer_header_is_redacted():
    assert "secret" not in _render("auth failed for Bearer secret.jwt.value")


def test_uvicorn_loggers_propagate_to_redacting_handler():
    configure_logging("INFO")
    for name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        lg = logging.getLogger(name)
        assert lg.propagate and not lg.handlers
