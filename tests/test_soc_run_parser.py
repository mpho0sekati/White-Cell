import whitecell.cli_enhanced as cli_mod


def test_parse_soc_run_without_execute():
    cli = cli_mod.EnhancedWhiteCellCLI()
    alert, action, target = cli._parse_soc_run(["suspicious", "powershell", "activity"])
    assert alert == "suspicious powershell activity"
    assert action is None
    assert target is None


def test_parse_soc_run_with_execute():
    cli = cli_mod.EnhancedWhiteCellCLI()
    alert, action, target = cli._parse_soc_run(
        ["credential", "dumping", "--execute", "block_ip", "10.0.0.8"]
    )
    assert alert == "credential dumping"
    assert action == "block_ip"
    assert target == "10.0.0.8"
