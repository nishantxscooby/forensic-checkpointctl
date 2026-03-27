"""MVP detection rules — explicit substring and port checks."""

from __future__ import annotations

from dataclasses import dataclass

from .normalize import NetworkConnection, NormalizedCheckpoint, Process

COMMON_PORTS = frozenset({80, 443, 22})

SUSPICIOUS_SUBSTRINGS = (
    "sh",
    "bash",
    "nc",
    "netcat",
    "curl",
    "wget",
)

SENSITIVE_MARKERS = (
    "/etc/shadow",
    "/etc/passwd",
    ".ssh",
    "/root",
)


@dataclass
class Finding:
    category: str
    item: str
    explanation: str


def _process_text(proc: Process) -> str:
    return f"{proc.command} {proc.cmdline}".lower()


def rule_suspicious_processes(norm: NormalizedCheckpoint) -> list[Finding]:
    out: list[Finding] = []
    for proc in norm.processes:
        text = _process_text(proc)
        matched = [s for s in SUSPICIOUS_SUBSTRINGS if s in text]
        if not matched:
            continue
        kinds = ", ".join(sorted(set(matched)))
        out.append(
            Finding(
                category="suspicious_process",
                item=f"pid={proc.pid} command={proc.command!r} cmdline={proc.cmdline!r}",
                explanation=(
                    f"Process name or command line contains suspicious substring(s): {kinds}. "
                    "These often appear in shells or common download/reverse-shell tooling."
                ),
            )
        )
    return out


def rule_sensitive_files(norm: NormalizedCheckpoint) -> list[Finding]:
    out: list[Finding] = []
    seen: set[tuple[int, str]] = set()
    for file_row in norm.files:
        path = file_row.path
        hits = [m for m in SENSITIVE_MARKERS if m in path]
        if not hits:
            continue
        key = (file_row.pid, path)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            Finding(
                category="sensitive_file",
                item=f"pid={file_row.pid} path={path}",
                explanation=(
                    f"Open file path matches sensitive pattern(s): {', '.join(hits)} "
                    "(credentials, keys, or privileged paths)."
                ),
            )
        )
    return out


def _connection_item(conn: NetworkConnection) -> str:
    return f"pid={conn.pid} {conn.detail}"


def rule_network_list_and_ports(norm: NormalizedCheckpoint) -> list[Finding]:
    """One finding per socket; extra finding when TCP/UDP uses ports outside {80, 443, 22}."""
    out: list[Finding] = []
    for conn in norm.connections:
        out.append(
            Finding(
                category="network_observation",
                item=_connection_item(conn),
                explanation="Socket / connection from checkpoint CRIU data.",
            )
        )
        if conn.kind not in ("TCP", "UDP") and "TCP" not in conn.kind and "UDP" not in conn.kind:
            continue
        ports = [conn.local_port, conn.remote_port]
        unusual = [pt for pt in ports if pt > 0 and pt not in COMMON_PORTS]
        if unusual:
            out.append(
                Finding(
                    category="network_uncommon_port",
                    item=_connection_item(conn),
                    explanation=(
                        f"Port(s) outside common set {{80, 443, 22}}: {unusual}. "
                        "Review in context of the workload."
                    ),
                )
            )
    return out


def run_all_rules(norm: NormalizedCheckpoint) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(rule_suspicious_processes(norm))
    findings.extend(rule_sensitive_files(norm))
    findings.extend(rule_network_list_and_ports(norm))
    return findings
