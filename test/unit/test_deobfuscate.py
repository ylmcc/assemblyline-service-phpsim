"""Pure deobfuscation tests. No PHP execution, no AL framework, no network. All
fixtures are synthetic (not the real campaign's exact obfuscation/content)."""
import base64
import codecs
import zlib

from phpsim.deobfuscate import resolve_literal_decode_chains


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def test_inline_literal_chain_with_junk_comments():
    payload = '<?php echo "hi"; ?>'
    encoded = _b64(payload)
    script = (
        "<?php /*aDvLrYfESuJNZIz8*/ eval /*niBUgtXZMZYKUrsDS*/ ( /*LpcEkFjmNZ6mOq*/ "
        f"base64_decode /*lNQL0v5GOstNz*/ ( '{encoded}' ) ) ; ?>"
    )
    layers = resolve_literal_decode_chains(script)
    assert len(layers) == 1
    assert layers[0].sink == "eval"
    assert layers[0].decoded_text == payload
    assert layers[0].functions_applied == ["base64_decode"]


def test_double_layer_base64_rot13_auto_detected():
    payload = '<?php echo "hi"; ?>'
    rot13ed = codecs.encode(payload, "rot_13")
    encoded = _b64(rot13ed)
    script = f"<?php eval(base64_decode('{encoded}')); ?>"
    layers = resolve_literal_decode_chains(script)
    assert len(layers) == 1
    assert layers[0].decoded_text == payload
    assert layers[0].functions_applied == ["base64_decode", "str_rot13 (auto-detected)"]


def test_nested_three_layer_gzinflate_base64():
    payload = '<?php echo "hi"; ?>'
    compressed = zlib.compress(payload.encode())[2:-4]  # raw deflate stream for gzinflate
    encoded = base64.b64encode(compressed).decode()
    script = f"<?php eval(gzinflate(base64_decode('{encoded}'))); ?>"
    layers = resolve_literal_decode_chains(script)
    assert len(layers) == 1
    assert layers[0].decoded_text == payload
    assert layers[0].functions_applied == ["base64_decode", "gzinflate"]


def test_variable_tracked_assignment_resolves_eval():
    payload = '<?php echo "hi"; ?>'
    encoded = _b64(payload)
    script = f"<?php $x = base64_decode('{encoded}'); eval($x); ?>"
    layers = resolve_literal_decode_chains(script)
    assert len(layers) == 1
    assert layers[0].decoded_text == payload
    assert layers[0].functions_applied == ["base64_decode"]


def test_variable_from_superglobal_is_unresolved_not_guessed():
    script = "<?php $x = $_REQUEST['code']; eval($x); ?>"
    layers = resolve_literal_decode_chains(script)
    assert layers == []


def test_undeclared_variable_is_unresolved():
    script = "<?php eval($neverAssigned); ?>"
    layers = resolve_literal_decode_chains(script)
    assert layers == []


def test_comment_shaped_text_inside_string_literal_is_preserved():
    # Real corpus sample: an operator IP hidden as literal text inside an echo'd
    # string, shaped to look like a comment. A quote-unaware stripper would destroy
    # it before any scanning ever sees it -- use a placeholder IP, not the real one.
    from phpsim.deobfuscate import strip_junk_comments

    snippet = "echo '<? --  ((/*192.0.2.55*/)) -- ?>';"
    assert "192.0.2.55" in strip_junk_comments(snippet)


def test_real_comments_outside_strings_are_still_stripped():
    from phpsim.deobfuscate import strip_junk_comments

    snippet = "<?php /*junk1*/ eval /*junk2*/ ('x');"
    stripped = strip_junk_comments(snippet)
    assert "junk1" not in stripped
    assert "junk2" not in stripped
    assert "eval" in stripped


def test_max_decode_depth_truncates_and_flags():
    # Four STACKED eval-wrapper layers (each layer's decoded content is itself
    # another eval(base64_decode(...)) call) -- this is what max_depth caps, as
    # opposed to inline nesting within a single expression (unbounded, tested above).
    text = '<?php echo "hi"; ?>'
    for _ in range(3):
        text = f"<?php eval(base64_decode('{_b64(text)}')); ?>"
    script = f"<?php eval(base64_decode('{_b64(text)}')); ?>"

    layers = resolve_literal_decode_chains(script, max_depth=2)
    assert len(layers) == 2  # capped before reaching the innermost layer
    assert layers[-1].truncated is True
