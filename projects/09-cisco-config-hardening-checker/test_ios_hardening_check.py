from pathlib import Path

from ios_hardening_check import check, score

HERE = Path(__file__).parent


def load(name):
    return (HERE / "samples" / name).read_text()


def failed(results):
    return {r.cid for r in results if not r.passed}


def test_before_config_fails_key_controls():
    res = check(load("fictional-access-switch-before.cfg"))
    assert {"AUTH-01", "AUTH-03", "MGMT-01", "MGMT-03", "MGMT-04", "MGMT-05",
            "SNMP-01", "SNMP-02", "L2-01", "L2-02", "L2-03"} <= failed(res)
    assert score(res) < 30


def test_after_config_passes_everything():
    res = check(load("fictional-access-switch-after.cfg"))
    assert failed(res) == set(), failed(res)
    assert score(res) == 100


def test_telnet_detected_in_mixed_transport():
    cfg = "line vty 0 4\n transport input telnet ssh\n access-class X in\n"
    assert "MGMT-01" in failed(check(cfg))
