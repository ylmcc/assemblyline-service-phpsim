# PhpSim

Docker Hub: [kylemc54321/assemblyline-service-phpsim](https://hub.docker.com/r/kylemc54321/assemblyline-service-phpsim)

An AssemblyLine v4 service that statically resolves literal-only (or simple
tracked-variable) `eval`/`assert`/`create_function` decode chains in PHP
(`base64_decode`/`str_rot13`/`gzinflate`/`gzuncompress`/`gzdecode`/`hex2bin`/`strrev`/
`urldecode`, arbitrarily nested) **without ever executing them**, and scans for
dangerous-sink taint from user input, auth-bypass gates, privilege-escalation idioms,
and a telephony-fraud primitive (`asterisk -rx ... channel originate`) -- surfacing
what a decoded webshell actually *does*, which the stock `DeobfuScripter`/
`ConfigExtractor` services don't (confirmed against real submissions: they unwrap the
same encoding layers but score 0 on these files, having no concept of dangerous-sink
taint or auth-bypass logic).

## Safety

**This service has no code-execution surface at all.** `deobfuscate.py` only ever
calls pure stdlib data-transform functions (`base64.b64decode`, `zlib.decompress`,
`codecs.decode(..., "rot_13")`, `bytes.fromhex`, string reversal, URL-decode) on
literal string text already present in the source, or on a value resolved from a
simple prior `$var = ...;` assignment tracked the same way `BashSim` tracks bash
variables. It never calls PHP's `eval`/`assert`/`create_function` itself, and no
`php` interpreter, `subprocess`, or shell is ever invoked anywhere in this service --
in development, in tests, or in its own runtime logic.

A dynamic `eval($x)` where `$x` isn't a literal-only or simple-assignment-tracked
decode chain (most commonly, a sink fed directly by `$_GET`/`$_POST`/`$_REQUEST`/
`$_COOKIE` at call time) is reported as unresolved (heuristic 7), never guessed at.
This is a fundamental limit, not just of static analysis: that value doesn't exist
until an attacker's live HTTP request supplies it, so a single sandboxed execution
pass wouldn't reveal it either (the script would just run with no such parameter set,
and that branch simply wouldn't fire).

## Submission parameters

| Param | Default | Purpose |
|---|---|---|
| `max_decode_depth` | 5 | Cap on how many stacked eval-wrapper layers get recursively unwrapped. |

## Development

This system's Python is externally managed (PEP 668); use an isolated virtualenv:

```bash
python3 -m venv .venv
.venv/bin/pip install pytest assemblyline-v4-service assemblyline-service-utilities
.venv/bin/pytest test/
```

No test in this repo ever executes PHP or contains the real campaign's exact
obfuscation (junk-comment content, the real auth-gate hash, the real operator IP) --
every fixture is a synthetic analogue built to exercise the same shape, using
placeholder hashes/extensions/IPs, matching the same discipline already established
in the sibling `PayloadFetcher`/`BashSim` services' test suites.
