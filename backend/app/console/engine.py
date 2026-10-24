"""Execute Command Deck input for a principal, with per-user session state and interactive prompts."""

from __future__ import annotations

import logging

from app.core.errors import ApiError
from app.core.security import Principal
from app.db import TenantDB, new_id, utcnow

from .commands import Ctx, Out, build_registry, session_expiry
from .parser import ConsoleError, Registry, tokenize

log = logging.getLogger(__name__)

REGISTRY: Registry = build_registry()
HISTORY_LIMIT = 100


def _load_session(principal: Principal) -> dict:
    tdb = TenantDB(principal.tenant_id)
    doc = tdb.console_sessions.find_one_and_update(
        {"user_id": principal.user_id},
        {"$setOnInsert": {"_id": new_id("cs"), "capture_id": None, "history": [], "pending": None, "created_at": utcnow()},
         "$set": {"expires_at": session_expiry()}},
        upsert=True, return_document=True)
    return doc


def _save_session(principal: Principal, session: dict) -> None:
    TenantDB(principal.tenant_id).console_sessions.update_one(
        {"user_id": principal.user_id},
        {"$set": {"capture_id": session.get("capture_id"), "pending": session.get("pending"),
                  "history": session.get("history", [])[-HISTORY_LIMIT:], "expires_at": session_expiry(), "updated_at": utcnow()}})


def _quote(v: str) -> str:
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"' if (" " in v or '"' in v or not v) else v


def _prompt_choices(principal: Principal, session: dict, kind: str) -> list[str]:
    tdb = TenantDB(principal.tenant_id)
    cap = session.get("capture_id")
    if kind == "capture":
        return [d["_id"] for d in tdb.captures.find({"deleted_at": None}, {"_id": 1}).sort("created_at", -1).limit(8)]
    if kind == "flow" and cap:
        return [d["local_id"] for d in tdb.flows.find({"capture_id": cap}, {"local_id": 1}).sort("issue_score", -1).limit(8)]
    if kind == "finding" and cap:
        return [d["short_id"] for d in tdb.findings.find({"capture_id": cap}, {"short_id": 1}).sort("seq", 1).limit(8)]
    if kind == "mission":
        from app.services.missions import MISSIONS

        return list(MISSIONS)
    return []


def execute(principal: Principal, line: str) -> dict:
    session = _load_session(principal)
    out = Out()
    line = (line or "").strip()
    response: dict = {"input": line}
    try:
        if not line:
            return {"input": line, "blocks": [], "capture_id": session.get("capture_id")}
        pending = session.get("pending")
        if pending:
            if line.lower() in ("cancel", "abort", "^c"):
                session["pending"] = None
                out.muted("Cancelled.")
                _save_session(principal, session)
                return {"input": line, "blocks": out.blocks, "capture_id": session.get("capture_id")}
            first = tokenize(line)[0].lower() if line else ""
            if not any(path[0] == first for path in REGISTRY.commands):
                line = f"{pending['line']} {_quote(line)}"
            session["pending"] = None
        tokens = tokenize(line)
        parsed = REGISTRY.parse(tokens, session)
        cmd = parsed.command
        if not principal.can(cmd.permission):
            raise ApiError(403, "forbidden", f"Your role cannot run '{cmd.name}' (requires {cmd.permission})")
        session.setdefault("history", []).append(line)
        if parsed.missing:
            spec = parsed.missing
            session["pending"] = {"line": line, "arg": spec.name}
            choices = spec.choices or _prompt_choices(principal, session, spec.kind)
            out.info(f"[?] {spec.prompt or f'Value for {spec.name}?'}")
            if choices:
                out.muted("    options: " + ", ".join(choices))
            response["prompt"] = {"command": cmd.name, "arg": spec.name, "message": spec.prompt, "choices": choices}
        else:
            ctx = Ctx(principal, session, out)
            cmd.handler(ctx, parsed.args, parsed.options)
            response["command"] = cmd.name
    except ConsoleError as exc:
        out.err(str(exc))
        if exc.suggestions:
            out.muted("Did you mean: " + " | ".join(exc.suggestions))
        response["error"] = True
    except ApiError as exc:
        out.err(exc.message)
        response["error"] = True
    except Exception:  # noqa: BLE001 - never leak internals to the terminal
        log.exception("console command failed")
        out.err("Internal error while running the command; it has been logged.")
        response["error"] = True
    _save_session(principal, session)
    response.update(blocks=out.blocks, capture_id=session.get("capture_id"))
    return response


def complete(principal: Principal, line: str) -> list[str]:
    """Context-aware completions for the current input line."""
    session = _load_session(principal)
    text = line.lstrip()
    trailing_space = text.endswith(" ")
    try:
        tokens = tokenize(text)
    except ConsoleError:
        return []
    names = REGISTRY.names()
    typed = " ".join(tokens).lower()
    if not tokens or (len(tokens) <= 2 and not any(typed == n or typed.startswith(n + " ") for n in names)):
        prefix = typed + (" " if trailing_space and tokens else "")
        return [n for n in names if n.startswith(prefix)][:20]
    try:
        cmd, rest = REGISTRY.match(tokens)
    except ConsoleError:
        return []
    idx = len(rest) if trailing_space else max(0, len(rest) - 1)
    partial = "" if trailing_space or not rest else rest[-1]
    if partial.startswith("--"):
        return [f"--{o.name}" for o in cmd.options if f"--{o.name}".startswith(partial)]
    if idx < len(cmd.args):
        spec = cmd.args[idx]
        choices = spec.choices or _prompt_choices(principal, session, spec.kind)
        return [c for c in choices if c.lower().startswith(partial.lower())][:20]
    return [f"--{o.name}" for o in cmd.options][:20]
