"""Format normalized data and findings as a plain-text report."""

from __future__ import annotations

from .normalize import NormalizedCheckpoint
from .rules import Finding


def render_report(norm: NormalizedCheckpoint, findings: list[Finding]) -> str:
    lines: list[str] = []
    lines.append("Checkpoint forensic report (MVP)")
    lines.append("=" * 50)
    lines.append(f"Container: {norm.container_name or '(unknown)'}")
    lines.append(f"Engine:    {norm.engine or '(unknown)'}")
    lines.append(f"Image:     {norm.image or '(unknown)'}")
    lines.append(f"ID:        {norm.checkpoint_id or '(unknown)'}")
    lines.append(
        f"Counts:    processes={len(norm.processes)} "
        f"open_paths={len(norm.files)} connections={len(norm.connections)}"
    )
    lines.append("")

    sections: dict[str, list[Finding]] = {
        "suspicious_process": [],
        "sensitive_file": [],
        "network": [],
    }
    for finding in findings:
        if finding.category in ("network_observation", "network_uncommon_port"):
            sections["network"].append(finding)
        elif finding.category == "suspicious_process":
            sections["suspicious_process"].append(finding)
        elif finding.category == "sensitive_file":
            sections["sensitive_file"].append(finding)

    lines.append("Suspicious Processes")
    lines.append("-" * 30)
    if not sections["suspicious_process"]:
        lines.append("No suspicious process indicators matched.")
    else:
        for finding in sections["suspicious_process"]:
            lines.append(f"  • {finding.item}")
            lines.append(f"    {finding.explanation}")
    lines.append("")

    lines.append("Sensitive File Access")
    lines.append("-" * 30)
    if not sections["sensitive_file"]:
        lines.append("No sensitive path patterns matched.")
    else:
        for finding in sections["sensitive_file"]:
            lines.append(f"  • {finding.item}")
            lines.append(f"    {finding.explanation}")
    lines.append("")

    lines.append("Network Activity")
    lines.append("-" * 30)
    if not sections["network"]:
        lines.append("No socket/connection records in JSON (empty or missing).")
    else:
        for finding in sections["network"]:
            lines.append(f"  • {finding.item}")
            lines.append(f"    {finding.explanation}")
    lines.append("")

    return "\n".join(lines)
