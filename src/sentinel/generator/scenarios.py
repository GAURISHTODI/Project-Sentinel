"""Benign traffic and labeled attack campaigns.

Attacker addresses come from the RFC 5737 documentation ranges, so nothing here can be mistaken
for a real host. A campaign is an iterator of events with a fixed attacker; timestamps are
assigned later by the generator.
"""

from __future__ import annotations

import random
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from urllib.parse import quote

from sentinel.common.schema import NormalizedEvent
from sentinel.generator import payloads as p

ATTACKER_NETS = ("203.0.113", "198.51.100")  # TEST-NET-3 / TEST-NET-2


@dataclass
class World:
    """Stable benign population: users with a home IP, plus heavy shared (NAT) addresses."""

    n_users: int = 500
    seed: int = 42
    users: list[str] = field(default_factory=list)
    home_ip: dict[str, str] = field(default_factory=dict)
    weights: list[float] = field(default_factory=list)

    def __post_init__(self) -> None:
        rng = random.Random(self.seed)
        for i in range(self.n_users):
            u = f"user{i:04d}"
            self.users.append(u)
            # five users (1%) share one NAT-like address: a benign higher-volume source
            self.home_ip[u] = (
                f"10.20.{rng.randint(0, 3)}.{rng.randint(1, 254)}" if i % 100 else "10.30.0.1"
            )
            self.weights.append(1.0 / (1 + i % 5))  # mild skew: some users are more active


Campaign = Callable[[random.Random, World], Iterator[NormalizedEvent]]


def attacker_ip(rng: random.Random) -> str:
    return f"{rng.choice(ATTACKER_NETS)}.{rng.randint(2, 250)}"


def _flow(rng: random.Random, packets: int, syn_only: bool) -> dict[str, float]:
    fwd = float(packets if syn_only else packets // 2 + 1)
    bwd = 0.0 if syn_only else float(packets // 2)
    dur = rng.uniform(0.001, 0.01) if syn_only else rng.uniform(0.05, 30.0)
    size = fwd * rng.uniform(40, 60) if syn_only else (fwd + bwd) * rng.uniform(200, 900)
    return {
        "duration": dur,
        "fwd_packets": fwd,
        "bwd_packets": bwd,
        "bytes": size,
        "syn_count": fwd if syn_only else 1.0,
        "pkts_per_sec": (fwd + bwd) / max(dur, 1e-6),
    }


# ------------------------------------------------------------------ benign


def benign_event(rng: random.Random, w: World) -> NormalizedEvent:
    user = rng.choices(w.users, weights=w.weights)[0]
    ip = w.home_ip[user]
    ua = rng.choice(p.BENIGN_UAS)
    r = rng.random()
    if r < 0.55:
        return NormalizedEvent(
            source="app",
            event_type="http_request",
            src_ip=ip,
            user=user,
            method="GET",
            path=rng.choice(p.BENIGN_PATHS),
            status=rng.choices([200, 304, 404], [90, 7, 3])[0],
            user_agent=ua,
            country="US",
            label="benign",
        )
    if r < 0.70:  # logins: about 4% typo failures, all benign
        ok = rng.random() > 0.04
        return NormalizedEvent(
            source="auth",
            event_type="login",
            src_ip=ip,
            user=user,
            method="POST",
            path="/login",
            status=200 if ok else 401,
            user_agent=ua,
            country="US",
            label="benign",
        )
    if r < 0.90:
        return NormalizedEvent(
            source="network",
            event_type="flow",
            src_ip=ip,
            dst_ip="10.0.0.5",
            dst_port=rng.choice([80, 443, 443, 443]),
            flow_features=_flow(rng, packets=rng.randint(8, 400), syn_only=False),
            label="benign",
        )
    name, parent, cmd = rng.choice(
        [
            ("chrome.exe", "explorer.exe", "chrome.exe --type=renderer"),
            ("outlook.exe", "explorer.exe", "outlook.exe"),
            ("powershell.exe", "explorer.exe", "powershell.exe Get-ChildItem C:\\Reports"),
            ("code.exe", "explorer.exe", "code.exe C:\\work"),
        ]
    )
    return NormalizedEvent(
        source="endpoint",
        event_type="process_create",
        src_ip=ip,
        user=user,
        process_name=name,
        parent_process=parent,
        command_line=cmd,
        label="benign",
    )


# ------------------------------------------------------------------ attacks


def brute_force(rng: random.Random, w: World) -> Iterator[NormalizedEvent]:
    ip, victim, ua = attacker_ip(rng), rng.choice(w.users), rng.choice(p.BENIGN_UAS)
    for _ in range(rng.randint(60, 200)):
        yield NormalizedEvent(
            source="auth",
            event_type="login",
            src_ip=ip,
            user=victim,
            method="POST",
            path="/login",
            status=401,
            user_agent=ua,
            country="RU",
            label="brute_force",
        )


def credential_stuffing(rng: random.Random, w: World) -> Iterator[NormalizedEvent]:
    ip, ua = attacker_ip(rng), rng.choice(p.BENIGN_UAS)
    for _ in range(rng.randint(80, 250)):
        yield NormalizedEvent(
            source="auth",
            event_type="login",
            src_ip=ip,
            user=rng.choice(w.users),
            method="POST",
            path="/login",
            status=401 if rng.random() < 0.97 else 200,
            user_agent=ua,
            country="CN",
            label="credential_stuffing",
        )


def _web_attack(label: str, plist: list[str], rng: random.Random) -> Iterator[NormalizedEvent]:
    ip, ua = attacker_ip(rng), rng.choice(p.BENIGN_UAS)
    for _ in range(rng.randint(15, 60)):
        param = rng.choice(["q", "id", "name", "redirect"])
        yield NormalizedEvent(
            source="app",
            event_type="http_request",
            src_ip=ip,
            method="GET",
            path=f"/search?{param}={quote(rng.choice(plist))}",
            status=rng.choice([200, 400, 500]),
            user_agent=ua,
            country="NL",
            label=label,
        )


def sqli(rng: random.Random, w: World) -> Iterator[NormalizedEvent]:
    return _web_attack("sqli", p.SQLI, rng)


def xss(rng: random.Random, w: World) -> Iterator[NormalizedEvent]:
    return _web_attack("xss", p.XSS, rng)


def path_traversal(rng: random.Random, w: World) -> Iterator[NormalizedEvent]:
    ip, ua = attacker_ip(rng), rng.choice(p.BENIGN_UAS)
    for _ in range(rng.randint(10, 40)):
        yield NormalizedEvent(
            source="app",
            event_type="http_request",
            src_ip=ip,
            method="GET",
            path=f"/static/{rng.choice(p.PATH_TRAVERSAL)}",
            status=rng.choice([400, 403, 404]),
            user_agent=ua,
            country="BR",
            label="path_traversal",
        )


def scanner(rng: random.Random, w: World) -> Iterator[NormalizedEvent]:
    ip, ua = attacker_ip(rng), rng.choice(p.SCANNER_UAS)
    for path in rng.choices(p.PROBE_PATHS, k=rng.randint(15, 30)):
        yield NormalizedEvent(
            source="app",
            event_type="http_request",
            src_ip=ip,
            method="GET",
            path=path,
            status=404,
            user_agent=ua,
            country="US",
            label="scanner",
        )


def port_scan(rng: random.Random, w: World) -> Iterator[NormalizedEvent]:
    ip = attacker_ip(rng)
    for port in rng.sample(range(1, 10000), k=rng.randint(60, 250)):
        yield NormalizedEvent(
            source="network",
            event_type="flow",
            src_ip=ip,
            dst_ip="10.0.0.5",
            dst_port=port,
            flow_features=_flow(rng, packets=rng.randint(1, 3), syn_only=True),
            label="port_scan",
        )


def dos(rng: random.Random, w: World) -> Iterator[NormalizedEvent]:
    ips = [attacker_ip(rng) for _ in range(rng.randint(1, 2))]
    ua = rng.choice(p.BENIGN_UAS)
    for _ in range(rng.randint(800, 2000)):  # sustained: a flood lasts tens of seconds
        yield NormalizedEvent(
            source="app",
            event_type="http_request",
            src_ip=rng.choice(ips),
            method="GET",
            path="/search?q=a",
            status=rng.choices([200, 503], [60, 40])[0],
            user_agent=ua,
            country="US",
            label="dos",
        )


def account_takeover(rng: random.Random, w: World) -> Iterator[NormalizedEvent]:
    """Valid credentials used from a never-seen IP and country (SEN-006)."""
    victim, ip = rng.choice(w.users), attacker_ip(rng)
    for _ in range(rng.randint(3, 8)):
        yield NormalizedEvent(
            source="auth",
            event_type="login",
            src_ip=ip,
            user=victim,
            method="POST",
            path="/login",
            status=200,
            user_agent=rng.choice(p.BENIGN_UAS),
            country="KP",
            label="valid_account_abuse",
        )


def endpoint_powershell(rng: random.Random, w: World) -> Iterator[NormalizedEvent]:
    host = w.home_ip[rng.choice(w.users)]
    for _ in range(rng.randint(2, 6)):
        yield NormalizedEvent(
            source="endpoint",
            event_type="process_create",
            src_ip=host,
            user=rng.choice(w.users),
            process_name="powershell.exe",
            parent_process="winword.exe",
            command_line=f"powershell.exe -NoP -W Hidden -EncodedCommand {p.ENCODED_PS}",
            label="endpoint_powershell",
        )


def endpoint_spawn(rng: random.Random, w: World) -> Iterator[NormalizedEvent]:
    host = w.home_ip[rng.choice(w.users)]
    for _ in range(rng.randint(2, 5)):
        yield NormalizedEvent(
            source="endpoint",
            event_type="process_create",
            src_ip=host,
            user=rng.choice(w.users),
            process_name=rng.choice(["cmd.exe", "wscript.exe"]),
            parent_process=rng.choice(["winword.exe", "excel.exe", "outlook.exe"]),
            command_line="cmd.exe /c whoami & hostname",
            label="endpoint_spawn",
        )


def endpoint_service(rng: random.Random, w: World) -> Iterator[NormalizedEvent]:
    host = w.home_ip[rng.choice(w.users)]
    yield NormalizedEvent(
        source="endpoint",
        event_type="service_install",
        src_ip=host,
        user=rng.choice(w.users),
        process_name="sc.exe",
        parent_process="cmd.exe",
        command_line="sc create UpdSvc binPath= C:\\Users\\Public\\upd.exe start= auto",
        label="endpoint_service",
    )


ATTACKS: dict[str, Campaign] = {
    "brute_force": brute_force,
    "credential_stuffing": credential_stuffing,
    "sqli": sqli,
    "xss": xss,
    "path_traversal": path_traversal,
    "scanner": scanner,
    "port_scan": port_scan,
    "dos": dos,
    "valid_account_abuse": account_takeover,
    "endpoint_powershell": endpoint_powershell,
    "endpoint_spawn": endpoint_spawn,
    "endpoint_service": endpoint_service,
}
