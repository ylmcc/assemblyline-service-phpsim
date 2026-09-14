"""PhpSim: statically resolves literal-only eval/assert/create_function decode
chains in PHP (base64/rot13/gzinflate, arbitrarily nested, including chains fed
through a simple tracked variable assignment) without ever executing them, and
scans for dangerous-sink taint from user input, auth-bypass gates, privilege-
escalation idioms, and a telephony-fraud primitive -- surfacing what a decoded
webshell actually does.

No `php` interpreter is ever invoked, no `eval`/`assert`/`create_function` is ever
called on PHP content, and no subprocess is ever spawned by this service -- see
README.md for the full safety rationale.
"""
from __future__ import annotations

import json
import os

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Heuristic, Result, ResultSection

from phpsim.deobfuscate import resolve_literal_decode_chains, strip_junk_comments
from phpsim.scanner import scan


def _add_kind_section(result: Result, findings: list, kinds: tuple[str, ...], heur_id: int,
                       title: str, format_line) -> None:
    matches = [f for f in findings if f.kind in kinds]
    if not matches:
        return
    section = ResultSection(title, body="\n".join(format_line(f) for f in matches))
    heur = Heuristic(heur_id)
    for f in matches:
        heur.add_signature_id(f.detail.get("sink", f.kind))
    section.set_heuristic(heur)
    result.add_section(section)


class PhpSim(ServiceBase):
    def execute(self, request: ServiceRequest) -> None:
        text = request.file_contents.decode("utf-8", errors="ignore")
        stripped = strip_junk_comments(text)

        layers = resolve_literal_decode_chains(stripped, max_depth=request.get_param("max_decode_depth"))

        findings = list(scan(stripped))
        for layer in layers:
            findings += scan(strip_junk_comments(layer.decoded_text))

        result = Result()

        if layers:
            decode_section = ResultSection(
                "Obfuscated eval/assert/create_function chain resolved",
                body="\n".join(
                    f"{l.sink}(...) via {' -> '.join(l.functions_applied) or '(no decoding needed)'}"
                    + (" [truncated: nested further than max_decode_depth]" if l.truncated else "")
                    for l in layers
                ),
            )
            decode_section.set_heuristic(5, signature="literal_decode_chain")
            result.add_section(decode_section)
            for i, layer in enumerate(layers):
                out_path = os.path.join(self.working_directory, f"decoded_layer_{i}.php")
                with open(out_path, "w") as f:
                    f.write(layer.decoded_text)
                request.add_extracted(
                    out_path, f"{request.sha256}_layer{i}_decoded.php",
                    f"Decoded {layer.sink}() payload (depth {layer.depth})",
                )

        def _fmt_sink(f):
            if f.kind == "code_exec_e_modifier":
                return "preg_replace with /e modifier (legacy code-execution gadget)"
            return f"{f.detail.get('sink')}({f.detail.get('arg', '')})"

        _add_kind_section(
            result, findings, ("direct_taint", "code_exec_e_modifier"), 1,
            "Dangerous sink directly reachable from user input",
            _fmt_sink,
        )
        _add_kind_section(
            result, findings, ("indirect_taint",), 2,
            "Dangerous sink reachable via a simple assignment from user input",
            _fmt_sink,
        )
        _add_kind_section(
            result, findings, ("auth_bypass_gate",), 3,
            "Hardcoded credential/auth-bypass gate detected",
            lambda f: f"md5(...) == {f.detail.get('hash')}",
        )
        _add_kind_section(
            result, findings, ("privilege_escalation",), 4,
            "Session forgery / privilege escalation pattern",
            lambda f: f.snippet,
        )
        _add_kind_section(
            result, findings, ("telephony_fraud_primitive",), 6,
            "Telephony-fraud primitive (Asterisk channel originate)",
            lambda f: f.snippet,
        )
        _add_kind_section(
            result, findings, ("dynamic_eval_unresolved",), 7,
            "Deobfuscation incomplete",
            lambda f: f"{f.detail.get('sink')}({f.detail.get('arg', '')}) -- not a literal/tracked-variable chain",
        )

        audit_log = {
            "layers": [
                {"depth": l.depth, "sink": l.sink, "functions_applied": l.functions_applied,
                 "truncated": l.truncated, "decoded_text_preview": l.decoded_text[:500]}
                for l in layers
            ],
            "findings": [{"kind": f.kind, "detail": f.detail, "snippet": f.snippet} for f in findings],
        }
        log_path = os.path.join(self.working_directory, "phpsim_findings_log.json")
        with open(log_path, "w") as f:
            json.dump(audit_log, f, indent=2)
        request.add_supplementary(log_path, "phpsim_findings_log.json", "Full deobfuscation/scan audit log")

        request.result = result
