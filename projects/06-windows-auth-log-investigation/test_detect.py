from pathlib import Path

import generate_synthetic_logs as gen
from detect import detect, load


def test_scenario_is_fully_detected_without_noise(tmp_path: Path):
    out = tmp_path / "log.csv"
    gen.main(out)
    alerts = detect(load(out))
    rules = [a.rule.split()[0] for a in alerts]
    assert sorted(rules) == sorted(["DET-01", "DET-02", "DET-03", "DET-04", "DET-05", "DET-06", "DET-07"])


def test_background_alone_raises_no_alerts(tmp_path: Path):
    import csv, random
    rows = sorted(gen.background(random.Random(gen.SEED)), key=lambda r: r["TimeCreated"])
    out = tmp_path / "bg.csv"
    with out.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=gen.FIELDS)
        w.writeheader()
        w.writerows(rows)
    assert detect(load(out)) == []
