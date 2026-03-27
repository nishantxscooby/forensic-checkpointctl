"""Load checkpointctl inspect JSON and normalize to MVP structures."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Process:
    pid: int
    command: str
    cmdline: str


@dataclass
class FileAccess:
    pid: int
    path: str


@dataclass
class NetworkConnection:
    pid: int
    protocol: str
    kind: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    detail: str


@dataclass
class NormalizedCheckpoint:
    container_name: str
    engine: str
    image: str
    checkpoint_id: str
    processes: list[Process] = field(default_factory=list)
    files: list[FileAccess] = field(default_factory=list)
    connections: list[NetworkConnection] = field(default_factory=list)


def _as_int(value: Any, default: int = 0) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _walk_process_tree(node: Any, out: list[Process]) -> None:
    if not isinstance(node, dict):
        return
    pid = _as_int(node.get("pid"), 0)
    out.append(
        Process(
            pid=pid,
            command=_as_str(node.get("command")),
            cmdline=_as_str(node.get("cmdline")),
        )
    )
    children = node.get("children")
    if isinstance(children, list):
        for child in children:
            _walk_process_tree(child, out)


def _collect_files(raw: dict[str, Any], out: list[FileAccess]) -> None:
    fds = raw.get("file_descriptors")
    if not isinstance(fds, list):
        return
    for entry in fds:
        if not isinstance(entry, dict):
            continue
        pid = _as_int(entry.get("pid"), 0)
        open_files = entry.get("open_files")
        if not isinstance(open_files, list):
            continue
        for open_file in open_files:
            if not isinstance(open_file, dict):
                continue
            path = _as_str(open_file.get("path")).strip()
            if path:
                out.append(FileAccess(pid=pid, path=path))


def _collect_connections(raw: dict[str, Any], out: list[NetworkConnection]) -> None:
    sks = raw.get("sockets")
    if not isinstance(sks, list):
        return
    for entry in sks:
        if not isinstance(entry, dict):
            continue
        pid = _as_int(entry.get("pid"), 0)
        open_sockets = entry.get("open_sockets")
        if not isinstance(open_sockets, list):
            continue
        for sock in open_sockets:
            if not isinstance(sock, dict):
                continue
            protocol = _as_str(sock.get("protocol"))
            data = sock.get("data")
            if not isinstance(data, dict):
                data = {}
            kind = _as_str(data.get("type"))
            src = _as_str(data.get("src"))
            dst = _as_str(data.get("dst"))
            sp = _as_int(data.get("src_port"), 0)
            dp = _as_int(data.get("dst_port"), 0)
            state = _as_str(data.get("state"))
            addr = _as_str(data.get("address"))

            if kind == "UNIX" or protocol.upper().startswith("UNIX"):
                detail = f"UNIX addr={addr or '(empty)'}"
                lip, rip = addr, ""
                lp, rp = 0, 0
            elif kind in ("TCP", "UDP") or protocol:
                detail = f"{kind or protocol} {src}:{sp} -> {dst}:{dp}"
                if state:
                    detail += f" state={state}"
                lip, rip = src, dst
                lp, rp = sp, dp
            else:
                detail = f"{protocol} kind={kind or '?'}"
                lip, rip = src, dst
                lp, rp = sp, dp

            out.append(
                NetworkConnection(
                    pid=pid,
                    protocol=protocol,
                    kind=kind or protocol or "unknown",
                    local_ip=lip,
                    local_port=lp,
                    remote_ip=rip,
                    remote_port=rp,
                    detail=detail.strip(),
                )
            )


def load_json_array(path: str) -> list[Any]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError(
            "Expected a JSON array at the root (checkpointctl emits a list of checkpoints)."
        )
    return data


def normalize_checkpoint(raw: dict[str, Any]) -> NormalizedCheckpoint:
    processes: list[Process] = []
    tree = raw.get("process_tree")
    if isinstance(tree, dict):
        _walk_process_tree(tree, processes)

    files: list[FileAccess] = []
    _collect_files(raw, files)

    connections: list[NetworkConnection] = []
    _collect_connections(raw, connections)

    return NormalizedCheckpoint(
        container_name=_as_str(raw.get("container_name")),
        engine=_as_str(raw.get("engine")),
        image=_as_str(raw.get("image")),
        checkpoint_id=_as_str(raw.get("id")),
        processes=processes,
        files=files,
        connections=connections,
    )
