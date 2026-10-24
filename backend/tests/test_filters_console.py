import pytest

from app.console.parser import ConsoleError, tokenize
from app.services.filters import FilterError, compile_filter


@pytest.mark.parametrize("expr", [
    "tcp", "ip.addr == 10.0.0.1", "tcp.port == 443 and not dns", "tcp.flags.reset == 1", "frame.len > 1000 || udp",
    "tcp.analysis.retransmission", "http.host contains \"example\"", "(ip.src == 10.0.0.1) && (tcp.dstport == 80 or tcp.dstport == 443)",
])
def test_valid_filters_compile(expr):
    compile_filter(expr)


@pytest.mark.parametrize("expr", [
    "ip.addr == 10.0.0.1; rm -rf /", "$(id)", "tcp.port == ", "unknown.field == 1", "a" * 1200, "(" * 40 + "tcp" + ")" * 40,
    "ip.addr == 999.1.1.1",
])
def test_invalid_filters_rejected(expr):
    with pytest.raises(FilterError):
        compile_filter(expr)


def test_tokenize_quotes_and_limits():
    assert tokenize('finding status F1 confirmed "verified with tmsh"') == ["finding", "status", "F1", "confirmed", "verified with tmsh"]
    assert tokenize("a '' b") == ["a", "", "b"]
    with pytest.raises(ConsoleError):
        tokenize('pcap inspect "unterminated')
    with pytest.raises(ConsoleError):
        tokenize("x " * 300)


def test_registry_parse_and_suggestions():
    from app.console.engine import REGISTRY

    parsed = REGISTRY.parse(["flow", "inspect", "t3"], {})
    assert parsed.command.name == "flow inspect" and parsed.args["flow"] == "t3"
    parsed = REGISTRY.parse(["flow", "inspect"], {})
    assert parsed.missing is not None and parsed.missing.name == "flow"  # interactive prompt
    with pytest.raises(ConsoleError) as exc:
        REGISTRY.parse(["tcp", "retransmisions"], {})
    assert "tcp retransmissions" in exc.value.suggestions
    with pytest.raises(ConsoleError):
        REGISTRY.parse(["flow", "inspect", "t3;ls"], {})
    with pytest.raises(ConsoleError):
        REGISTRY.parse(["findings", "list", "--severity", "urgent"], {})
