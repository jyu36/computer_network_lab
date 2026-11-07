"""Persist detailed machine-readable results and display a compact comparison."""

import csv
import json
from collections import Counter


class BehaviorFailure(AssertionError):
    """A measured contract violation with evidence for mutation attribution."""

    def __init__(self, code, message, **details):
        super().__init__(message)
        self.code = code
        self.details = details


def save_results(directory, results):
    """Write one row per configuration and case to JSON and CSV."""
    (directory / "summary.json").write_text(json.dumps(results, indent=2) + "\n")
    with (directory / "summary.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=[
                "configuration",
                "id",
                "stage",
                "status",
                "profile",
                "max_host_pairs",
                "pair_seed",
                "duration_seconds",
                "forwarding_table_checks",
                "error",
            ],
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(results)


def format_summary(results):
    """Show pass counts by requirement group, keeping errors distinct from failures."""
    lines = [
        "Configuration                 Base     Block    Move     Runtime  Outcome"
    ]
    if any(row.get("profile") == "sampled" for row in results):
        lines.insert(
            0,
            "SAMPLED development results: forwarding/ping may cover fewer host pairs; see events.json.",
        )
    for name in dict.fromkeys(row["configuration"] for row in results):
        rows = [row for row in results if row["configuration"] == name]
        counts = Counter(row["status"] for row in rows)
        groups = []
        for stage in ("base", "blocklist", "movement", "runtime"):
            selected = [row for row in rows if row["stage"] == stage]
            groups.append(
                "%d/%d"
                % (sum(row["status"] == "PASS" for row in selected), len(selected))
                if selected
                else "-"
            )
        outcome = (
            "PASS"
            if counts["PASS"] == len(rows)
            else ", ".join(
                "%d %s" % (count, status) for status, count in sorted(counts.items())
            )
        )
        lines.append("%-29s %-8s %-8s %-8s %-8s %s" % (name, *groups, outcome))
        table_counts = Counter()
        for row in rows:
            table_counts.update(row.get("forwarding_table_checks", {}))
        if table_counts:
            lines.append(
                "  Forwarding tables: %d verified, %d failed, %d inconclusive"
                % tuple(
                    table_counts[status] for status in ("PASS", "FAIL", "INCONCLUSIVE")
                )
            )
    if any(
        row.get("forwarding_table_checks", {}).get("INCONCLUSIVE") for row in results
    ):
        lines.append(
            "INCONCLUSIVE tables are not verified; case PASS does not imply all table checks passed. See analysis.json for unsupported/controller branches."
        )
    for row in results:
        if row["status"] != "PASS":
            lines.append(
                "%s / %s: %s — %s"
                % (
                    row["configuration"],
                    row["id"],
                    row["status"],
                    row.get("error", row.get("cleanup_error", "")),
                )
            )
    return "\n".join(lines)
