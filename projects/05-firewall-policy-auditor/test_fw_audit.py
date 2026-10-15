from pathlib import Path

from fw_audit import audit, parse_config

HERE = Path(__file__).parent


def ids(findings):
    return {f.rule_id for f in findings}


def test_parser_reads_policies_and_interfaces():
    cfg = parse_config((HERE / "samples/fictional-branch-fw.conf").read_text())
    assert set(cfg["firewall policy"]) == {"1", "2", "3", "4", "5", "6"}
    assert cfg["system interface"]["port1"]["role"] == ["wan"]
    assert cfg["firewall policy"]["3"]["service"] == ["HTTP", "HTTPS", "DNS"]


def test_insecure_sample_flags_expected_issues():
    f = audit((HERE / "samples/fictional-branch-fw.conf").read_text())
    expected = {"FW-001", "FW-003", "FW-004", "FW-005", "FW-006", "FW-007", "FW-008",
                "FW-009", "FW-010", "MGMT-001", "MGMT-003", "MGMT-004", "MGMT-005", "MGMT-006"}
    assert expected <= ids(f)
    # RDP exposed from WAN must be critical
    assert any(x.rule_id == "FW-003" and x.severity == "critical" for x in f)


def test_shadowing_detects_rule_covered_by_any_any():
    f = audit((HERE / "samples/fictional-branch-fw.conf").read_text())
    shadowed = [x.obj for x in f if x.rule_id == "FW-009"]
    assert any("policy 5" in s for s in shadowed)


def test_hardened_sample_is_clean():
    f = audit((HERE / "samples/fictional-hardened-fw.conf").read_text())
    assert not [x for x in f if x.severity in ("critical", "high")], f


def test_admin_names_are_not_echoed():
    f = audit((HERE / "samples/fictional-branch-fw.conf").read_text())
    assert not any("lab-admin" in x.obj for x in f)
