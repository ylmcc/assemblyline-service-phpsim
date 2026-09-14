"""Literal-only decode-chain resolution and simple variable tracking for PHP
obfuscation, without ever executing PHP.

Only pure stdlib data transforms (base64/zlib/codecs/binascii on literal string
text already present in the source, or on a value resolved from a simple prior
`$var = ...;` assignment) are ever applied. No `eval`/`assert` of PHP is ever
called here -- this module only decodes bytes, it never runs code.
"""
from __future__ import annotations

import base64
import codecs
import re
import urllib.parse
import zlib
from dataclasses import dataclass, field
from typing import Optional


# All decode functions operate on/return latin-1 ("byte-faithful": every byte 0-255
# round-trips to a unique character and back with zero loss) rather than UTF-8
# internally. Intermediate values in a chain like gzinflate(base64_decode('...'))
# are raw compressed bytes, not text yet -- decoding them as UTF-8 mid-chain would
# lossily mangle any byte that isn't valid UTF-8 before the next decode step ever
# sees it. Only the final, fully-resolved result is converted to real UTF-8 text,
# once, in _resolve_layer.

def _b64_decode(s: str) -> str:
    cleaned = "".join(s.split())
    padded = cleaned + "=" * (-len(cleaned) % 4)
    return base64.b64decode(padded, validate=False).decode("latin-1")


def _gzinflate(s: str) -> str:
    return zlib.decompress(s.encode("latin-1"), -15).decode("latin-1")


def _gzuncompress(s: str) -> str:
    return zlib.decompress(s.encode("latin-1")).decode("latin-1")


def _gzdecode(s: str) -> str:
    return zlib.decompress(s.encode("latin-1"), 16 + zlib.MAX_WBITS).decode("latin-1")


def _hex2bin(s: str) -> str:
    return bytes.fromhex("".join(s.split())).decode("latin-1")


DECODE_FUNCS = {
    "base64_decode": _b64_decode,
    "str_rot13": lambda s: codecs.decode(s, "rot_13"),
    "gzinflate": _gzinflate,
    "gzuncompress": _gzuncompress,
    "gzdecode": _gzdecode,
    "hex2bin": _hex2bin,
    "strrev": lambda s: s[::-1],
    "urldecode": lambda s: urllib.parse.unquote(s, encoding="latin-1"),
    "rawurldecode": lambda s: urllib.parse.unquote(s, encoding="latin-1"),
}

_PHP_MARKERS = ("<?php", "function", "$_", "echo", "system(", "eval(")


def strip_junk_comments(text: str) -> str:
    """Remove /* ... */ comments -- the real corpus's obfuscation inserts a random
    junk comment between every token. Does not touch // or # line comments."""
    return re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)


def _looks_like_php(text: str) -> bool:
    return any(marker in text for marker in _PHP_MARKERS)


def _maybe_auto_rot13(text: str) -> tuple[str, bool]:
    """Real corpus samples stack base64(rot13(source)). If a decoded layer doesn't
    look like PHP but rot13-transforming it does, apply rot13. Returns (text, applied)."""
    if _looks_like_php(text):
        return text, False
    rotated = codecs.decode(text, "rot_13")
    if _looks_like_php(rotated):
        return rotated, True
    return text, False


_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_VAR_RE = re.compile(r"\$(\w+)")
_ASSIGN_RE = re.compile(r"\$(\w+)\s*=(?!=)\s*")


def _skip_ws(text: str, i: int) -> int:
    n = len(text)
    while i < n and text[i].isspace():
        i += 1
    return i


def _parse_string_literal(text: str, i: int) -> tuple[Optional[str], int]:
    """text[i] must be a quote character. Returns (content, index_after_closing_quote),
    or (None, len(text)) if unterminated."""
    quote = text[i]
    n = len(text)
    j = i + 1
    buf = []
    while j < n:
        c = text[j]
        if c == "\\" and j + 1 < n:
            nxt = text[j + 1]
            if quote == "'":
                if nxt in ("\\", "'"):
                    buf.append(nxt)
                    j += 2
                    continue
                buf.append(c)
                j += 1
                continue
            else:
                mapping = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "$": "$"}
                if nxt in mapping:
                    buf.append(mapping[nxt])
                    j += 2
                    continue
                buf.append(c)
                j += 1
                continue
        if c == quote:
            return "".join(buf), j + 1
        buf.append(c)
        j += 1
    return None, j


@dataclass
class _ParseState:
    functions_applied: list = field(default_factory=list)


def _parse_value(text: str, i: int, env: dict, state: _ParseState) -> tuple[Optional[str], int]:
    """Parse one atom at i: a string literal, a $var lookup, or an IDENT(...) call
    where IDENT is a known decode function whose sole argument itself resolves."""
    i = _skip_ws(text, i)
    n = len(text)
    if i >= n:
        return None, i

    c = text[i]
    if c in ("'", '"'):
        return _parse_string_literal(text, i)

    m = _VAR_RE.match(text, i)
    if m:
        name = m.group(1)
        j = m.end()
        entry = env.get(name)
        if entry is None:
            return None, j
        val, funcs = entry
        state.functions_applied.extend(funcs)
        return val, j

    m = _IDENT_RE.match(text, i)
    if m:
        name = m.group(0)
        j = _skip_ws(text, m.end())
        if j < n and text[j] == "(":
            depth = 1
            k = j + 1
            arg_start = k
            while k < n and depth > 0:
                ch = text[k]
                if ch in ("'", '"'):
                    _, k = _parse_string_literal(text, k)
                    continue
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        break
                k += 1
            arg_end = k
            close_j = k + 1 if k < n else k
            if name in DECODE_FUNCS:
                inner_val, inner_end = _parse_concat(text, arg_start, env, state)
                inner_end_ws = _skip_ws(text, inner_end) if inner_val is not None else None
                if inner_val is not None and inner_end_ws == arg_end:
                    try:
                        decoded = DECODE_FUNCS[name](inner_val)
                    except Exception:
                        return None, close_j
                    state.functions_applied.append(name)
                    return decoded, close_j
                return None, close_j
            return None, close_j  # unknown/unsupported function -- can't resolve
        return None, j
    return None, i


def _parse_concat(text: str, i: int, env: dict, state: _ParseState) -> tuple[Optional[str], int]:
    """Parse `value ('.' value)*` -- simple PHP string concatenation of resolvable
    atoms (e.g. 'prefix' . base64_decode('...'))."""
    val, j = _parse_value(text, i, env, state)
    if val is None:
        return None, j
    parts = [val]
    n = len(text)
    while True:
        k = _skip_ws(text, j)
        if k < n and text[k] == "." and not (k + 1 < n and text[k + 1] == "="):
            k2 = _skip_ws(text, k + 1)
            v2, j2 = _parse_value(text, k2, env, state)
            if v2 is None:
                return None, j2
            parts.append(v2)
            j = j2
        else:
            break
    return "".join(parts), j


def resolve_expression(text: str, i: int, env: dict) -> tuple[Optional[str], int, list]:
    """Resolve the expression starting at index i as far as possible using only
    literals and prior `env` variable bindings. Returns
    (value_or_None, next_index, functions_applied)."""
    state = _ParseState()
    val, j = _parse_concat(text, i, env, state)
    return val, j, state.functions_applied


def build_variable_env(text: str) -> dict:
    """Single left-to-right pass tracking simple `$var = <resolvable expr>;`
    assignments, mirroring BashSim's env/SymValue approach for bash, so a later
    `eval($var)` can be resolved even when the decode chain isn't written inline.
    Unresolvable assignments are simply omitted (a later lookup then correctly
    misses -> reported unresolved, never guessed at)."""
    env: dict = {}
    for m in _ASSIGN_RE.finditer(text):
        name = m.group(1)
        val, _end, funcs = resolve_expression(text, m.end(), env)
        if val is not None:
            env[name] = (val, funcs)
    return env


@dataclass
class DecodedLayer:
    depth: int
    sink: str  # "eval" | "assert" | "create_function"
    decoded_text: str
    functions_applied: list
    truncated: bool


_SINK_RE = re.compile(r"\b(eval|assert|create_function)\s*\(")


def _find_sink_calls(text: str):
    """Yield (sink_name, arg_start_index, arg_end_index) for each eval/assert/
    create_function(...) call site in `text`, using paren-depth counting."""
    n = len(text)
    for m in _SINK_RE.finditer(text):
        sink = m.group(1)
        j = m.end()
        depth = 1
        k = j
        while k < n and depth > 0:
            ch = text[k]
            if ch in ("'", '"'):
                _, k = _parse_string_literal(text, k)
                continue
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        yield sink, j, k


def resolve_literal_decode_chains(text: str, max_depth: int = 5) -> list[DecodedLayer]:
    """Find sink(decode_fn(decode_fn(...)))/sink($trackedVar) shapes and return each
    fully-resolved decoded layer, recursing into decoded content up to max_depth.
    Never executes anything -- only pure stdlib data transforms on literal or
    tracked-variable text already present in the source."""
    layers: list[DecodedLayer] = []
    _resolve_layer(text, depth=0, max_depth=max_depth, layers=layers)
    return layers


def _resolve_layer(text: str, depth: int, max_depth: int, layers: list[DecodedLayer]) -> None:
    stripped = strip_junk_comments(text)
    env = build_variable_env(stripped)
    for sink, arg_start, arg_end in _find_sink_calls(stripped):
        val, end_idx, funcs = resolve_expression(stripped, arg_start, env)
        if val is None:
            continue
        end_idx_ws = _skip_ws(stripped, end_idx)
        if end_idx_ws != arg_end:
            continue  # didn't consume the whole argument (e.g. extra comma-separated args)

        if funcs:
            # val is a byte-faithful latin-1 internal representation (it passed
            # through at least one binary decode step) -- convert to real text now
            # that we have the final, fully-decoded bytes.
            val = val.encode("latin-1").decode("utf-8", errors="replace")

        final_text, rot13_applied = _maybe_auto_rot13(val)
        applied = list(funcs) + (["str_rot13 (auto-detected)"] if rot13_applied else [])

        truncated = False
        if depth + 1 >= max_depth:
            truncated = bool(_SINK_RE.search(strip_junk_comments(final_text)))

        layers.append(DecodedLayer(
            depth=depth, sink=sink, decoded_text=final_text,
            functions_applied=applied, truncated=truncated,
        ))

        if depth + 1 < max_depth:
            _resolve_layer(final_text, depth + 1, max_depth, layers)
