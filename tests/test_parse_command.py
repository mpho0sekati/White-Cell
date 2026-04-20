from whitecell.engine import parse_command


def test_parse_command_empty():
    cmd, args = parse_command("")
    assert cmd == ""
    assert args == []


def test_parse_command_with_args():
    cmd, args = parse_command("agent deploy a1 30")
    assert cmd == "agent"
    assert args == ["deploy", "a1", "30"]
