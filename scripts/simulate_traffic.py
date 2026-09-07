"""Traffic simulator generating live high-volume traffic scenarios through the Zero-Trust Gateway pipeline."""

import argparse
import random
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.common.schemas import (
    AuditRecord,
    GraphNode,
    GraphPath,
    RequestContext,
    Resource,
    Subject,
)
from app.gateway.interceptor import ZeroTrustInterceptor
from app.policy.client import SpiceDBClient


class InMemoryRedisMock:
    """Lightweight in-memory Redis mock for offline standalone simulations."""

    def __init__(self) -> None:
        self._data: dict[str, str] = {}
        self._sets: dict[str, set[str]] = {}
        self._zsets: dict[str, list[tuple[float, str]]] = {}
        self._lists: dict[str, list[str]] = {}

    def get(self, key: str) -> str | None:
        return self._data.get(key)

    def setex(self, key: str, ttl: int, value: str) -> bool:
        self._data[key] = value
        return True

    def sismember(self, key: str, member: str) -> int:
        return 1 if member in self._sets.get(key, set()) else 0

    def sadd(self, key: str, member: str) -> int:
        if key not in self._sets:
            self._sets[key] = set()
        self._sets[key].add(member)
        return 1

    def lpush(self, key: str, value: str) -> int:
        if key not in self._lists:
            self._lists[key] = []
        self._lists[key].insert(0, value)
        return len(self._lists[key])

    def ltrim(self, key: str, start: int, stop: int) -> bool:
        if key in self._lists:
            self._lists[key] = self._lists[key][start : stop + 1]
        return True

    def lrange(self, key: str, start: int, stop: int) -> list[str]:
        return self._lists.get(key, [])[start : stop + 1]

    def pipeline(self) -> Any:
        return InMemoryRedisPipeline(self)


class InMemoryRedisPipeline:
    """Mock pipeline executing on InMemoryRedisMock."""

    def __init__(self, store: InMemoryRedisMock) -> None:
        self.store = store
        self._ops: list[tuple[str, Any]] = []

    def zadd(self, key: str, mapping: dict[str, float]) -> None:
        self._ops.append(("zadd", (key, mapping)))

    def zremrangebyscore(self, key: str, min_score: Any, max_score: Any) -> None:
        self._ops.append(("zrem", (key, min_score, max_score)))

    def zcount(self, key: str, min_score: Any, max_score: Any) -> None:
        self._ops.append(("zcount", (key, min_score, max_score)))

    def zcard(self, key: str) -> None:
        self._ops.append(("zcard", key))

    def expire(self, key: str, ttl: int) -> None:
        self._ops.append(("expire", (key, ttl)))

    def setex(self, key: str, ttl: int, value: str) -> None:
        self._ops.append(("setex", (key, ttl, value)))

    def lpush(self, key: str, value: str) -> None:
        self._ops.append(("lpush", (key, value)))

    def ltrim(self, key: str, start: int, stop: int) -> None:
        self._ops.append(("ltrim", (key, start, stop)))

    def execute(self) -> list[Any]:
        results: list[Any] = []
        for op, args in self._ops:
            if op == "zadd":
                key, mapping = args
                if key not in self.store._zsets:
                    self.store._zsets[key] = []
                for m, s in mapping.items():
                    self.store._zsets[key].append((float(s), str(m)))
                results.append(len(mapping))
            elif op == "zrem":
                key, min_s, max_s = args
                items = self.store._zsets.get(key, [])
                self.store._zsets[key] = [(s, m) for s, m in items if s > float(max_s)]
                results.append(0)
            elif op == "zcount":
                key, min_s, max_s = args
                items = self.store._zsets.get(key, [])
                c = sum(1 for s, _ in items if s >= float(min_s))
                results.append(c)
            elif op == "zcard":
                key = args
                results.append(len(self.store._zsets.get(key, [])))
            elif op == "setex":
                key, ttl, val = args
                self.store.setex(key, ttl, val)
                results.append(True)
            elif op == "lpush":
                key, val = args
                results.append(self.store.lpush(key, val))
            elif op == "ltrim":
                results.append(True)
            elif op == "expire":
                results.append(True)
        return results


def print_banner(title: str) -> None:
    """Print visual section banner."""
    print(f"\n{'=' * 78}")
    print(f"  {title.upper()}")
    print(f"{'=' * 78}")


def print_decision_summary(record: AuditRecord) -> None:
    """Format and print decision results and SHAP attributions."""
    decision = record.decision
    trust = decision.trust_score

    status_tag = f"[{decision.action.upper()}]"
    print(f"\nDecision Result: {status_tag}")
    print(f"  Reason:          {decision.reason}")
    print(f"  Trust Score:     {trust.score:.4f} (Previous: {trust.previous_score:.4f})")
    print(f"  Raw Anomaly:     {trust.raw_anomaly_score:.4f}")
    if trust.decay_amount > 0:
        print(f"  Decay Deducted: -{trust.decay_amount:.4f}")
    if trust.recovery_amount > 0:
        print(f"  Recovery Added: +{trust.recovery_amount:.4f}")

    if decision.narrow_applied:
        print("  [!] Closed-loop policy feedback: Restriction relation written to SpiceDB!")

    print("\nSHAP Feature Attribution (Why the model made this decision):")
    for attr in record.attributions[:4]:
        dir_marker = "[-]" if attr.direction == "anomalous" else "[+]"
        print(
            f"  {dir_marker} {attr.feature_name:<28} Value: {attr.feature_value:<8} "
            f"Impact: {attr.contribution_score * 100:>5.1f}% ({attr.direction})"
        )


def build_simulation_interceptor() -> ZeroTrustInterceptor:
    """Build interceptor configured with in-memory state stores for instant local demo."""
    mock_spicedb = MagicMock(spec=SpiceDBClient)
    mock_spicedb.check_access.return_value = True

    def mock_expand_path(
        subject: Any,
        resource: Any,
        permission: str = "view",
    ) -> list[GraphPath]:
        s_id = subject.id if hasattr(subject, "id") else str(subject)
        r_id = resource.id if hasattr(resource, "id") else str(resource)

        if "alice" in s_id:
            return [
                GraphPath(
                    nodes=[
                        GraphNode(type="user", id="alice"),
                        GraphNode(type="team", id="eng", relation="member"),
                        GraphNode(type="document", id=r_id, relation="reader"),
                    ],
                    hop_count=2,
                )
            ]
        elif "bob" in s_id:
            return [
                GraphPath(
                    nodes=[
                        GraphNode(type="user", id="bob"),
                        GraphNode(type="document", id=r_id, relation="reader"),
                    ],
                    hop_count=1,
                ),
                GraphPath(
                    nodes=[
                        GraphNode(type="user", id="bob"),
                        GraphNode(type="team", id="eng", relation="member"),
                        GraphNode(type="document", id=r_id, relation="reader"),
                    ],
                    hop_count=2,
                ),
            ]
        elif "charlie" in s_id:
            return [
                GraphPath(
                    nodes=[
                        GraphNode(type="user", id="charlie"),
                        GraphNode(type="team", id="security", relation="admin"),
                        GraphNode(type="document", id=r_id, relation="admin"),
                    ],
                    hop_count=2,
                )
            ]
        return []

    mock_spicedb.expand_path.side_effect = mock_expand_path
    redis_mock = InMemoryRedisMock()

    return ZeroTrustInterceptor(
        spicedb_client=mock_spicedb,
        redis_client=redis_mock,
    )


def generate_high_volume_stream(total_count: int = 300) -> list[RequestContext]:
    """Generate a realistic high-volume sequence of at least total_count requests.

    Mixes normal traffic with bursts, geo-velocity jumps, privilege shortcuts, and spoofing attacks.
    """
    requests: list[RequestContext] = []
    base_time = 1788789600.0  # 14:00 UTC (business hours)

    # 1. Benign requests (65% of total)
    benign_count = int(total_count * 0.65)
    for i in range(benign_count):
        user_choice = random.choice(["alice", "bob", "charlie"])
        session_id = f"sess_benign_{user_choice}_{i % 10}"
        resource_id = "doc1" if user_choice != "charlie" else random.choice(["doc1", "financials"])
        req_time = base_time + (i * 30.0) + random.uniform(0, 10)

        requests.append(
            RequestContext(
                session_id=session_id,
                subject=Subject(type="user", id=user_choice),
                resource=Resource(type="document", id=resource_id),
                permission="view",
                timestamp=req_time,
                ip_address=f"192.168.1.{10 + (i % 20)}",
                latitude=37.7749 + random.uniform(-0.01, 0.01),
                longitude=-122.4194 + random.uniform(-0.01, 0.01),
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                device_id=f"dev_{user_choice}_mbp",
            )
        )

    # 2. Rapid Volumetric Burst Anomaly (10% of total)
    burst_count = int(total_count * 0.10)
    burst_start_time = base_time + 4000.0
    for i in range(burst_count):
        requests.append(
            RequestContext(
                session_id="sess_burst_attacker",
                subject=Subject(type="user", id="bob"),
                resource=Resource(type="document", id="doc1"),
                permission="view",
                timestamp=burst_start_time + (i * 0.05),  # 20 requests/sec
                ip_address="10.0.0.99",
                latitude=37.7749,
                longitude=-122.4194,
                user_agent="Python-urllib/3.11 (ScraperBot)",
                device_id="dev_bob_mbp",
            )
        )

    # 3. Impossible Travel / High Geo-Velocity Anomaly (10% of total)
    travel_count = int(total_count * 0.10)
    travel_time = base_time + 8000.0
    cities = [
        ("San Francisco", 37.7749, -122.4194),
        ("Tokyo", 35.6762, 139.6503),
        ("London", 51.5074, -0.1278),
        ("Sydney", -33.8688, 151.2093),
    ]
    for i in range(travel_count):
        city_from = cities[i % len(cities)]
        city_to = cities[(i + 1) % len(cities)]
        sess_id = f"sess_travel_{i}"

        # First location
        requests.append(
            RequestContext(
                session_id=sess_id,
                subject=Subject(type="user", id="alice"),
                resource=Resource(type="document", id="doc1"),
                permission="view",
                timestamp=travel_time + (i * 120.0),
                latitude=city_from[1],
                longitude=city_from[2],
                user_agent="Mozilla/5.0",
                device_id="dev_alice_mbp",
            )
        )
        # Instant jump to second location (10 seconds later, thousands of km away)
        requests.append(
            RequestContext(
                session_id=sess_id,
                subject=Subject(type="user", id="alice"),
                resource=Resource(type="document", id="doc1"),
                permission="view",
                timestamp=travel_time + (i * 120.0) + 10.0,
                latitude=city_to[1],
                longitude=city_to[2],
                user_agent="Mozilla/5.0",
                device_id="dev_alice_mbp",
            )
        )

    # 4. Off-Hours & Device Fingerprint Mismatch Attack (15% of total)
    spoof_count = int(total_count * 0.15)
    off_hours_base = 1788746400.0  # 02:00 AM (off-hours deviation)
    for i in range(spoof_count):
        requests.append(
            RequestContext(
                session_id=f"sess_rogue_device_{i}",
                subject=Subject(type="user", id="charlie"),
                resource=Resource(type="document", id="financials"),
                permission="view",
                timestamp=off_hours_base + (i * 15.0),
                ip_address=f"198.51.100.{i % 50}",
                latitude=55.7558,  # Moscow
                longitude=37.6173,
                user_agent="RogueHardwareScanner/2.4",
                device_id="unknown_unregistered_hardware_attacker",
            )
        )

    # Sort sequentially by timestamp to simulate real live ingress stream
    requests.sort(key=lambda r: r.timestamp)
    return requests[:total_count] if len(requests) > total_count else requests


def run_high_volume_simulation(request_count: int = 300) -> None:
    """Execute high-volume traffic stream through the Zero-Trust interceptor."""
    interceptor = build_simulation_interceptor()
    requests = generate_high_volume_stream(total_count=request_count)

    print("\n" + "#" * 78)
    print(f"  ZERO-TRUST GATEWAY: SIMULATING {len(requests)} LIVE TRAFFIC REQUESTS")
    print("#" * 78)

    action_counts: dict[str, int] = {"allow": 0, "step_up": 0, "narrow": 0, "deny": 0}
    shap_driver_counts: dict[str, int] = {}
    total_decay = 0.0
    total_trust_sum = 0.0
    closed_loop_restrictions = 0

    start_eval_time = time.perf_counter()

    for idx, req in enumerate(requests, 1):
        record = interceptor.evaluate_request(req)
        decision = record.decision
        action = decision.action.lower()

        action_counts[action] = action_counts.get(action, 0) + 1
        total_trust_sum += decision.trust_score.score
        total_decay += decision.trust_score.decay_amount

        if decision.narrow_applied:
            closed_loop_restrictions += 1

        for driver in record.top_anomaly_drivers:
            shap_driver_counts[driver] = shap_driver_counts.get(driver, 0) + 1

        # Live visual progress bar
        if idx % 25 == 0 or idx == len(requests):
            pct = (idx / len(requests)) * 100
            filled = int(pct // 4)
            bar = "#" * filled + "-" * (25 - filled)
            print(
                f"\r[Progress: [{bar}] {pct:>5.1f}% ({idx}/{len(requests)})] "
                f"ALLOW: {action_counts['allow']} | "
                f"STEP_UP: {action_counts['step_up']} | "
                f"NARROW: {action_counts['narrow']} | "
                f"DENY: {action_counts['deny']}",
                end="",
                flush=True,
            )

    elapsed_s = time.perf_counter() - start_eval_time
    avg_latency_ms = (elapsed_s / len(requests)) * 1000.0

    print("\n")
    print_banner("Comprehensive Simulation & Anomaly Metrics Breakdown")

    print(f"Total Requests Evaluated:       {len(requests):,}")
    print(f"Total Evaluation Elapsed Time:  {elapsed_s:.3f} seconds")
    print(f"Average Pipeline Latency:       {avg_latency_ms:.2f} ms / request")
    print(f"Average System Trust Score:     {(total_trust_sum / len(requests)):.4f}")
    print(f"Total Cumulative Trust Decay:  -{total_decay:.4f}")
    print(f"Closed-Loop SpiceDB Writes:     {closed_loop_restrictions} automated restriction tuples")

    print("\n" + "-" * 78)
    print(f"{'DECISION ACTION':<20} | {'REQUEST COUNT':<15} | {'PERCENTAGE':<15}")
    print("-" * 78)
    for act, count in action_counts.items():
        pct = (count / len(requests)) * 100.0
        print(f"{act.upper():<20} | {count:<15} | {pct:>6.2f}%")
    print("-" * 78)

    print("\nTOP AGGREGATED SHAP ANOMALY DRIVERS DETECTED:")
    sorted_drivers = sorted(shap_driver_counts.items(), key=lambda x: x[1], reverse=True)
    for driver, occurrences in sorted_drivers[:6]:
        print(f"  [-] {driver:<32} Triggered in {occurrences:>3} anomalous decisions")

    print("\n" + "#" * 78)
    print(f"  SIMULATION COMPLETE: {len(requests)} REQUESTS PROCESSED SUCCESSFULLY")
    print("#" * 78 + "\n")


def main() -> None:
    """CLI entrypoint with configurable request count."""
    parser = argparse.ArgumentParser(
        description="Zero-Trust Gateway High-Volume Traffic Simulator"
    )
    parser.add_argument(
        "--count",
        "--requests",
        "-n",
        dest="count",
        type=int,
        default=300,
        help="Number of total requests to simulate (minimum 250, default: 300)",
    )
    args = parser.parse_args()

    count = max(250, args.count)
    run_high_volume_simulation(request_count=count)


if __name__ == "__main__":
    main()
