"""Regex/string-based scanning for dangerous-sink taint, auth-bypass gates, and
privilege-escalation idioms in PHP source -- grounded in real webshell samples
observed in this session's corpus. Never executes anything; pure text scanning.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .deobfuscate import build_variable_env, resolve_expression

_DANGEROUS_SINKS = ("system", "exec", "shell_exec", "passthru", "popen", "proc_open", "pcntl_exec")
_CODE_EXEC_SINKS = ("eval", "assert", "create_function")
_ALL_SINK_RE = re.compile(r"\b(" + "|".join(_DANGEROUS_SINKS + _CODE_EXEC_SINKS) + r")\s*\(")

_SUPERGLOBAL_RE = re.compile(r"\$_(GET|POST|REQUEST|FILES|COOKIE)\b")
_ASSIGN_FROM_SUPERGLOBAL_RE = re.compile(r"\$(\w+)\s*=\s*\$_(GET|POST|REQUEST|FILES|COOKIE)\b")
_AUTH_GATE_RE = re.compile(
    r"md5\s*\(\s*\$_(?:GET|POST|REQUEST)\[[^\]]+\]\s*\)\s*==\s*['\"]([0-9a-fA-F]{32})['\"]"
    r"|['\"]([0-9a-fA-F]{32})['\"]\s*==\s*md5\s*\(\s*\$_(?:GET|POST|REQUEST)\[[^\]]+\]\s*\)"
)
_ASTERISK_ORIGINATE_RE = re.compile(r"asterisk\s+-rx.{0,120}channel\s+originate", re.IGNORECASE | re.DOTALL)
_SETADMIN_RE = re.compile(r"->\s*setAdmin\s*\(")
_DB_OPEN_RE = re.compile(r"\b(sqlite_open|new\s+SQLite3|mysqli_connect|mysql_connect)\s*\(")
_SESSION_ASSIGN_RE = re.compile(r"\$_SESSION\s*\[")
_PREG_REPLACE_RE = re.compile(r"preg_replace\s*\(")
_PREG_PATTERN_RE = re.compile(r"\s*(['\"])(.)((?:(?!\2).)*)\2([a-zA-Z]*)\1", re.DOTALL)


@dataclass
class Finding:
    kind: str
    detail: dict = field(default_factory=dict)
    snippet: str = ""


def _skip_ws(text: str, i: int) -> int:
    n = len(text)
    while i < n and text[i].isspace():
        i += 1
    return i


def _extract_balanced_args(text: str, open_paren_idx: int) -> tuple[str, int]:
    """Given the index of an opening '(', return (arg_text, index_of_matching ')')."""
    n = len(text)
    depth = 1
    k = open_paren_idx + 1
    start = k
    while k < n and depth > 0:
        ch = text[k]
        if ch in ("'", '"'):
            quote = ch
            k += 1
            while k < n and text[k] != quote:
                if text[k] == "\\" and k + 1 < n:
                    k += 2
                    continue
                k += 1
            k += 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                break
        k += 1
    return text[start:k], k


def _snippet(text: str, start: int, end: int, pad: int = 20) -> str:
    return text[max(0, start - pad):min(len(text), end + pad)].strip()


def scan(text: str) -> list[Finding]:
    findings: list[Finding] = []
    env = build_variable_env(text)
    tainted_vars = {m.group(1) for m in _ASSIGN_FROM_SUPERGLOBAL_RE.finditer(text)}

    for m in _ALL_SINK_RE.finditer(text):
        sink = m.group(1)
        open_paren = m.end() - 1
        arg_text, arg_end = _extract_balanced_args(text, open_paren)

        has_direct = bool(_SUPERGLOBAL_RE.search(arg_text))
        has_indirect = (not has_direct) and any(
            re.search(r"\b" + re.escape(v) + r"\b", arg_text) for v in tainted_vars
        )

        if has_direct:
            findings.append(Finding("direct_taint", {"sink": sink, "arg": arg_text.strip()},
                                     _snippet(text, m.start(), open_paren + 1)))
        elif has_indirect:
            findings.append(Finding("indirect_taint", {"sink": sink, "arg": arg_text.strip()},
                                     _snippet(text, m.start(), open_paren + 1)))
        elif sink in _CODE_EXEC_SINKS:
            # Only flag as unresolved if deobfuscate.py's own resolver also couldn't
            # resolve this call site -- avoids double-reporting a call already
            # surfaced via the literal-decode-chain heuristic.
            val, end_idx, _funcs = resolve_expression(text, open_paren + 1, env)
            resolved = val is not None and _skip_ws(text, end_idx) == arg_end
            if not resolved:
                findings.append(Finding("dynamic_eval_unresolved", {"sink": sink, "arg": arg_text.strip()},
                                         _snippet(text, m.start(), open_paren + 1)))

    for m in _AUTH_GATE_RE.finditer(text):
        h = m.group(1) or m.group(2)
        findings.append(Finding("auth_bypass_gate", {"hash": h}, _snippet(text, m.start(), m.end())))

    priv_esc_match = _SETADMIN_RE.search(text)
    if priv_esc_match is None and _DB_OPEN_RE.search(text) and _SESSION_ASSIGN_RE.search(text):
        priv_esc_match = _DB_OPEN_RE.search(text)
    if priv_esc_match:
        findings.append(Finding("privilege_escalation", {}, _snippet(text, priv_esc_match.start(), priv_esc_match.end())))

    telephony_match = _ASTERISK_ORIGINATE_RE.search(text)
    if telephony_match:
        findings.append(Finding("telephony_fraud_primitive", {}, _snippet(text, telephony_match.start(), telephony_match.end())))

    for m in _PREG_REPLACE_RE.finditer(text):
        arg_text, _end = _extract_balanced_args(text, m.end() - 1)
        pm = _PREG_PATTERN_RE.match(arg_text)
        if pm and "e" in pm.group(4):
            findings.append(Finding("code_exec_e_modifier", {}, _snippet(text, m.start(), m.end())))

    return findings
