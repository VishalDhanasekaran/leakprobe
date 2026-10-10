"""Seeded-fault validation: run every lab profile and compare against its ``expected:`` map.

A *positive* is a FAIL (a leak or weakness detected). Per test ID and overall:
precision = TP / (TP + FP) and recall = TP / (TP + FN), where TP is expected and measured
FAIL, FP is measured FAIL where something else was expected, and FN is expected FAIL but
measured anything else. Agreement is an exact status match over all cells with ground truth.
"""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from leakprobe.lab.profile import TEST_IDS, Profile
from leakprobe.models import Report, Status
from leakprobe.report.jsonout import from_json, to_json

POSITIVE = Status.FAIL.value


@dataclass(frozen=True)
class Cell:
    """One profile x test result."""

    measured: str | None  # None: the test did not run
    expected: str | None  # None: no ground truth for this cell

    @property
    def judged(self) -> bool:
        return self.expected is not None

    @property
    def agrees(self) -> bool:
        return self.measured == self.expected


@dataclass(frozen=True)
class Score:
    """Confusion counts for the FAIL class plus exact agreement."""

    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    agree: int = 0
    judged: int = 0

    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else None

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else None

    @property
    def agreement(self) -> float | None:
        return self.agree / self.judged if self.judged else None


@dataclass
class Matrix:
    """Rows are profiles, columns are test IDs."""

    tests: tuple[str, ...] = TEST_IDS
    rows: dict[str, dict[str, Cell]] = field(default_factory=dict)

    def add(self, profile: str, expected: Mapping[str, str], report: Report) -> None:
        measured = {f.test_id: f.status.value for f in report.findings}
        self.rows[profile] = {
            t: Cell(measured.get(t), expected.get(t)) for t in self.tests
        }

    def cells(self, test_id: str | None = None) -> list[Cell]:
        return [
            cell for row in self.rows.values() for t, cell in row.items()
            if test_id is None or t == test_id
        ]

    def disagreements(self) -> list[tuple[str, str, Cell]]:
        return [
            (p, t, c) for p, row in self.rows.items() for t, c in row.items()
            if c.judged and not c.agrees
        ]


def score(cells: Sequence[Cell]) -> Score:
    """Confusion counts over the cells that have ground truth."""
    tp = fp = fn = tn = agree = judged = 0
    for c in cells:
        if not c.judged:
            continue
        judged += 1
        agree += c.agrees
        exp_pos, got_pos = c.expected == POSITIVE, c.measured == POSITIVE
        tp += exp_pos and got_pos
        fp += got_pos and not exp_pos
        fn += exp_pos and not got_pos
        tn += not exp_pos and not got_pos
    return Score(tp, fp, fn, tn, agree, judged)


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.0f}%"


def _cell(c: Cell) -> str:
    got = (c.measured or "not run").upper()
    if not c.judged:
        return f"{got} ·"
    return f"{got} ✓" if c.agrees else f"**{got}** ✗ (exp {(c.expected or '').upper()})"


def to_markdown(m: Matrix, title: str = "LeakProbe validation matrix") -> str:
    """Profiles x tests table, per-test precision/recall, and the disagreements."""
    total = score(m.cells())
    lines = [
        f"# {title}",
        "",
        f"- **Agreement:** {total.agree}/{total.judged} ({_pct(total.agreement)})",
        f"- **Precision (FAIL):** {_pct(total.precision)}  "
        f"**Recall (FAIL):** {_pct(total.recall)}",
        f"- TP {total.tp} · FP {total.fp} · FN {total.fn} · TN {total.tn}",
        "",
        "✓ matches `expected:`, ✗ disagrees, · no ground truth for this cell.",
        "",
        "| Profile | " + " | ".join(m.tests) + " |",
        "|---|" + "---|" * len(m.tests),
    ]
    for profile, row in m.rows.items():
        lines.append(f"| {profile} | " + " | ".join(_cell(row[t]) for t in m.tests) + " |")

    lines += ["", "## Per test", "", "| Test | Agreement | Precision | Recall | TP | FP | FN |"]
    lines.append("|---|---|---|---|---|---|---|")
    for t in m.tests:
        s = score(m.cells(t))
        if s.judged:
            lines.append(
                f"| {t} | {s.agree}/{s.judged} | {_pct(s.precision)} | {_pct(s.recall)} "
                f"| {s.tp} | {s.fp} | {s.fn} |"
            )

    bad = m.disagreements()
    lines += ["", "## Disagreements", ""]
    lines += [
        f"- {p} {t}: measured {(c.measured or 'not run').upper()}, "
        f"expected {(c.expected or '').upper()}"
        for p, t, c in bad
    ] or ["None."]
    return "\n".join(lines) + "\n"


def build(
    profiles: Sequence[Profile],
    measure: Callable[[Profile], Report],
    save_dir: Path | None = None,
    on_profile: Callable[[str], None] = lambda name: None,
) -> Matrix:
    """Measure every profile (``measure`` builds the lab and runs the suite)."""
    m = Matrix()
    for profile in profiles:
        on_profile(profile.name)
        report = measure(profile)
        if save_dir is not None:
            save_dir.mkdir(parents=True, exist_ok=True)
            (save_dir / f"{profile.name}.json").write_text(to_json(report) + "\n")
        m.add(profile.name, profile.expected, report)
    return m


def from_dir(profiles: Sequence[Profile], directory: Path) -> Matrix:
    """Rebuild the matrix from reports saved by ``build(save_dir=...)``; no root needed."""
    m = Matrix()
    for profile in profiles:
        path = directory / f"{profile.name}.json"
        if not path.exists():
            raise FileNotFoundError(f"no saved report for {profile.name}: {path}")
        m.add(profile.name, profile.expected, from_json(path.read_text()))
    return m
