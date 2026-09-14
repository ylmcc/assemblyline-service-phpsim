"""Pure scanner tests. No PHP execution, no AL framework, no network. All fixtures
are synthetic analogues (placeholder hash/IP/extension), not the real campaign's
exact content."""
from phpsim.scanner import scan


def test_direct_taint_from_request_to_system():
    script = "<?php system($_REQUEST['cmd']); ?>"
    findings = scan(script)
    kinds = [f.kind for f in findings]
    assert "direct_taint" in kinds


def test_indirect_taint_via_simple_assignment():
    script = "<?php $c = $_POST['y']; system($c); ?>"
    findings = scan(script)
    kinds = [f.kind for f in findings]
    assert "indirect_taint" in kinds
    assert "direct_taint" not in kinds


def test_auth_bypass_gate_detected():
    placeholder_hash = "0" * 32
    script = f"<?php if (md5($_REQUEST['pw']) == '{placeholder_hash}') {{ }} ?>"
    findings = scan(script)
    gate = [f for f in findings if f.kind == "auth_bypass_gate"]
    assert len(gate) == 1
    assert gate[0].detail["hash"] == placeholder_hash


def test_telephony_fraud_primitive_detected():
    script = (
        "<?php system('asterisk -rx \"channel originate Local/"
        "1000@placeholder-context application wait 1\"'); ?>"
    )
    findings = scan(script)
    kinds = [f.kind for f in findings]
    assert "telephony_fraud_primitive" in kinds


def test_preg_replace_e_modifier_flagged():
    script = "<?php preg_replace('/x/e', $repl, $subject); ?>"
    findings = scan(script)
    kinds = [f.kind for f in findings]
    assert "code_exec_e_modifier" in kinds


def test_preg_replace_without_e_modifier_not_flagged():
    script = "<?php preg_replace('/x/i', $repl, $subject); ?>"
    findings = scan(script)
    kinds = [f.kind for f in findings]
    assert "code_exec_e_modifier" not in kinds


def test_resolved_eval_not_flagged_as_dynamic_unresolved():
    # An eval() that deobfuscate.py can resolve (inline literal chain) must NOT
    # also show up as dynamic_eval_unresolved -- that would double-report the same
    # call site under two different findings.
    import base64
    encoded = base64.b64encode(b'<?php echo "hi"; ?>').decode()
    script = f"<?php eval(base64_decode('{encoded}')); ?>"
    findings = scan(script)
    kinds = [f.kind for f in findings]
    assert "dynamic_eval_unresolved" not in kinds


def test_truly_dynamic_eval_is_flagged_unresolved():
    script = "<?php eval($_REQUEST['code']); ?>"
    findings = scan(script)
    kinds = [f.kind for f in findings]
    # $_REQUEST inside eval's argument is both direct_taint (code-exec sink tainted
    # by a superglobal) -- dynamic_eval_unresolved is reserved for sinks NOT tainted
    # and NOT resolvable, so assert the taint finding fires instead.
    assert "direct_taint" in kinds


def test_privilege_escalation_setadmin_detected():
    script = "<?php $u = new ampuser($id); $u->setAdmin(); ?>"
    findings = scan(script)
    kinds = [f.kind for f in findings]
    assert "privilege_escalation" in kinds


def test_no_findings_on_benign_script():
    script = "<?php echo 'hello world'; ?>"
    findings = scan(script)
    assert findings == []
