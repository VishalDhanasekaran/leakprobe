"""JSON serialisation of reports (round-trips through the Report model)."""

from leakprobe.models import Report


def to_json(report: Report) -> str:
    """Serialise a report to indented JSON."""
    return report.model_dump_json(indent=2)


def from_json(text: str) -> Report:
    """Parse a report previously written by ``to_json``."""
    return Report.model_validate_json(text)
