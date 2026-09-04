"""Persistent enrollment/heartbeat test simulator; this is not the production endpoint agent."""
import argparse
import json
import os
import random
import statistics
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def post(url, body, headers=None):
    started = time.perf_counter()
    try:
        with urlopen(Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json", **(headers or {})}), timeout=15) as response:
            return json.load(response), (time.perf_counter() - started) * 1000, response.status
    except HTTPError as exc:
        return None, (time.perf_counter() - started) * 1000, exc.code


def percentile(values, fraction):
    return values[min(len(values) - 1, int(len(values) * fraction))] if values else 0


def save_state(path, identities):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps({"version": 1, "identities": identities}), encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--enrollment-token")
    parser.add_argument("--state-file", type=Path, default=Path("loadtest/agent-identities.state.json"))
    parser.add_argument("--devices", type=int, default=500)
    parser.add_argument("--concurrency", type=int, default=16)
    parser.add_argument("--duration-seconds", type=int, default=0)
    parser.add_argument("--interval-min", type=float, default=55)
    parser.add_argument("--interval-max", type=float, default=65)
    parser.add_argument("--burst", action="store_true")
    parser.add_argument("--results-file", type=Path)
    args = parser.parse_args()
    if args.state_file.exists():
        identities = json.loads(args.state_file.read_text(encoding="utf-8"))["identities"]
        if len(identities) != args.devices:
            raise SystemExit(f"state contains {len(identities)} devices, expected {args.devices}")
        resumed = True
    else:
        if not args.enrollment_token:
            raise SystemExit("--enrollment-token is required when no state file exists")
        def enroll(index):
            value, _, code = post(args.url + "/api/v1/agents/enroll", {"enrollment_token": args.enrollment_token, "installation_id": f"sim-{uuid.uuid4()}", "hostname": f"SIM-{index:04d}", "os_name": "Windows", "os_version": "11", "architecture": "x64", "initial_ip": f"10.20.{index // 254}.{index % 254 + 1}", "agent_version": "simulator-0.2"})
            if code != 201:
                raise RuntimeError(f"enrollment failed with HTTP {code}")
            return value
        with ThreadPoolExecutor(args.concurrency) as pool:
            identities = list(pool.map(enroll, range(args.devices)))
        save_state(args.state_file, identities)
        resumed = False

    def beat(index):
        identity = identities[index]
        body = {"device_id": identity["device_id"], "timestamp": datetime.now(timezone.utc).isoformat(), "hostname": f"SIM-{index:04d}", "username": f"user{index}", "agent_version": "simulator-0.2", "os_name": "Windows", "os_version": "11", "active_ips": [f"10.20.{index // 254}.{index % 254 + 1}"], "mac_addresses": [f"02:00:{index // 65536:02x}:{index // 256 % 256:02x}:{index % 256:02x}:01"], "uptime_seconds": 3600 + int(time.monotonic())}
        _, latency, code = post(args.url + "/api/v1/agents/heartbeat", body, {"X-Agent-Credential": identity["credential"]})
        return time.monotonic(), latency, code

    started = time.monotonic()
    observations = []
    if args.burst or not args.duration_seconds:
        with ThreadPoolExecutor(args.concurrency) as pool:
            observations = list(pool.map(beat, range(args.devices)))
    else:
        due = [started + random.uniform(0, args.interval_max) for _ in identities]
        with ThreadPoolExecutor(args.concurrency) as pool:
            while time.monotonic() - started < args.duration_seconds:
                now = time.monotonic()
                ready = [index for index, value in enumerate(due) if value <= now]
                if ready:
                    batch = list(pool.map(beat, ready))
                    observations.extend(batch)
                    for index in ready:
                        due[index] = now + random.uniform(args.interval_min, args.interval_max)
                else:
                    time.sleep(min(0.1, min(due) - now))
    elapsed = time.monotonic() - started
    successes = [item for item in observations if item[2] == 200]
    latencies = sorted(item[1] for item in successes)
    first = sorted(item[1] for item in successes if item[0] - started <= 300)
    last = sorted(item[1] for item in successes if item[0] - started >= max(0, elapsed - 300))
    window = lambda values: {"p50_ms": percentile(values, .50), "p95_ms": percentile(values, .95), "p99_ms": percentile(values, .99)}
    result = {"devices": len(identities), "resumed": resumed, "duration_seconds": round(elapsed, 3), "heartbeats": len(observations), "successes": len(successes), "errors": len(observations) - len(successes), "average_requests_per_second": len(observations) / elapsed if elapsed else 0, **window(latencies), "first_5_minutes": window(first), "last_5_minutes": window(last), "mean_ms": statistics.fmean(latencies) if latencies else 0}
    rendered = json.dumps(result, indent=2)
    if args.results_file:
        args.results_file.write_text(rendered, encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()
