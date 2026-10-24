"""PacketOps Command Deck: tokenizer, argument validation and command registry.

Input is never passed to a shell. Tokens are split with a small quote-aware
lexer, validated against each command's argument specification, and handed to
Python handlers that call the same service layer as the REST API.
"""

from __future__ import annotations

import difflib
import re
from collections.abc import Callable
from dataclasses import dataclass, field

MAX_LINE = 512
MAX_TOKENS = 24

ARG_PATTERNS = {
    "capture": re.compile(r"^(cap_[0-9a-f]{20}|[A-Za-z0-9._ -]{1,128})$"),
    "flow": re.compile(r"^((cap_[0-9a-f]{20}-)?[tu]\d{1,9})$"),
    "finding": re.compile(r"^((cap_[0-9a-f]{20}-)?F\d{1,6})$", re.I),
    "mission": re.compile(r"^[a-z0-9-]{2,40}$"),
    "int": re.compile(r"^\d{1,9}$"),
    "ip": re.compile(r"^[0-9a-fA-F:.]{2,45}$"),
    "word": re.compile(r"^[A-Za-z0-9_.:/-]{1,64}$"),
    "text": re.compile(r"^[^\x00-\x08\x0b-\x1f\x7f]{1,2000}$"),
}


class ConsoleError(ValueError):
    def __init__(self, message: str, suggestions: list[str] | None = None):
        super().__init__(message)
        self.suggestions = suggestions or []


def tokenize(line: str) -> list[str]:
    if len(line) > MAX_LINE:
        raise ConsoleError(f"Command longer than {MAX_LINE} characters")
    tokens, buf, quote, has_token = [], [], None, False
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == "\\" and i + 1 < len(line) and line[i + 1] in (quote, "\\"):
                buf.append(line[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            else:
                buf.append(ch)
        elif ch in ("'", '"'):
            quote, has_token = ch, True
        elif ch.isspace():
            if buf or has_token:
                tokens.append("".join(buf))
                buf, has_token = [], False
        else:
            buf.append(ch)
        i += 1
    if quote:
        raise ConsoleError("Unterminated quote")
    if buf or has_token:
        tokens.append("".join(buf))
    if len(tokens) > MAX_TOKENS:
        raise ConsoleError("Too many arguments")
    return tokens


@dataclass
class Arg:
    name: str
    kind: str = "word"
    required: bool = True
    prompt: str | None = None
    choices: list[str] | None = None
    help: str = ""
    rest: bool = False  # consumes the remaining tokens as one value (free text)
    session_default: str | None = None  # e.g. "capture_id": falls back to the selected capture


@dataclass
class Opt:
    name: str
    kind: str = "word"
    choices: list[str] | None = None
    help: str = ""
    default: str | int | None = None


@dataclass
class Command:
    path: tuple[str, ...]
    summary: str
    handler: Callable
    args: list[Arg] = field(default_factory=list)
    options: list[Opt] = field(default_factory=list)
    permission: str = "console:use"
    needs_capture: bool = False
    examples: list[str] = field(default_factory=list)
    category: str = "general"

    @property
    def name(self) -> str:
        return " ".join(self.path)

    def usage(self) -> str:
        parts = [self.name]
        for a in self.args:
            parts.append(f"<{a.name}>" if a.required and not a.session_default else f"[{a.name}]")
        for o in self.options:
            parts.append(f"[--{o.name} {o.kind}]")
        return " ".join(parts)


@dataclass
class Parsed:
    command: Command
    args: dict
    options: dict
    missing: Arg | None = None


class Registry:
    def __init__(self) -> None:
        self.commands: dict[tuple[str, ...], Command] = {}

    def register(self, cmd: Command) -> None:
        self.commands[cmd.path] = cmd

    def names(self) -> list[str]:
        return sorted(c.name for c in self.commands.values())

    def match(self, tokens: list[str]) -> tuple[Command, list[str]]:
        lowered = [t.lower() for t in tokens]
        for n in (3, 2, 1):
            if len(lowered) >= n and tuple(lowered[:n]) in self.commands:
                return self.commands[tuple(lowered[:n])], tokens[n:]
        typed = " ".join(lowered[:2])
        close = difflib.get_close_matches(typed, self.names(), n=3, cutoff=0.5)
        prefix = [n for n in self.names() if n.startswith(lowered[0])] if lowered else []
        suggestions = list(dict.fromkeys(close + prefix))[:5]
        raise ConsoleError(f"Unknown command: {' '.join(tokens[:3])}", suggestions)

    def parse(self, tokens: list[str], session: dict) -> Parsed:
        cmd, rest = self.match(tokens)
        positional: list[str] = []
        options: dict = {o.name: o.default for o in cmd.options}
        i = 0
        while i < len(rest):
            tok = rest[i]
            if tok.startswith("--") and len(tok) > 2:
                name = tok[2:].lower()
                opt = next((o for o in cmd.options if o.name == name), None)
                if not opt:
                    raise ConsoleError(f"Unknown option --{name} for '{cmd.name}'", [cmd.usage()])
                if i + 1 >= len(rest):
                    raise ConsoleError(f"Option --{name} needs a value", [cmd.usage()])
                options[name] = self._validate(opt.kind, rest[i + 1], opt.choices, f"--{name}")
                i += 2
                continue
            positional.append(tok)
            i += 1
        args: dict = {}
        for idx, spec in enumerate(cmd.args):
            if spec.rest:
                val = " ".join(positional[idx:]) if len(positional) > idx else None
            else:
                val = positional[idx] if len(positional) > idx else None
            if val is None and spec.session_default:
                val = session.get(spec.session_default)
            if val is None:
                if spec.required:
                    return Parsed(cmd, args, options, missing=spec)
                continue
            args[spec.name] = self._validate(spec.kind, val, spec.choices, spec.name)
        extra = len(positional) - len(cmd.args)
        if extra > 0 and not any(a.rest for a in cmd.args):
            raise ConsoleError(f"Too many arguments for '{cmd.name}'", [cmd.usage()])
        return Parsed(cmd, args, options)

    @staticmethod
    def _validate(kind: str, value: str, choices: list[str] | None, label: str):
        if choices is not None:
            if value.lower() not in choices:
                raise ConsoleError(f"{label} must be one of: {', '.join(choices)}")
            return value.lower()
        pat = ARG_PATTERNS.get(kind)
        if pat and not pat.match(value):
            raise ConsoleError(f"Invalid value for {label}: {value[:40]!r}")
        if kind == "int":
            return int(value)
        return value
