"""Synthetic telemetry: a simulated company (world), benign behaviour (baseline)
and attack replays (scenarios). Used for live demos, model training and evaluation."""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

from aegis.simulator.baseline import BaselineSimulator, event_time
from aegis.simulator.scenarios import DESCRIPTIONS, SCENARIOS, run_scenario

__all__ = ["BaselineSimulator", "SCENARIOS", "DESCRIPTIONS", "run_scenario", "build_dataset", "event_time"]


def build_dataset(
    days: float,
    seed: int,
    start: datetime | None = None,
    attacks_per_day: float = 0.0,
    attack_names: list[str] | None = None,
) -> list[dict]:
    """Benign traffic for `days`, optionally with attack scenarios injected at random times.

    Returns raw envelopes sorted by time - exactly what the collectors consume.
    """
    start = start or datetime(2026, 9, 7, tzinfo=UTC)  # a Monday
    sim = BaselineSimulator(seed)
    envs = list(sim.generate(start, hours=days * 24))
    rng = random.Random(seed + 1000)
    names = attack_names or list(SCENARIOS)
    n_attacks = round(days * attacks_per_day)
    for i in range(n_attacks):
        name = names[i % len(names)]
        at = start + timedelta(seconds=rng.uniform(3600, days * 86400 - 3600))
        envs.extend(run_scenario(name, at, seed=rng.randint(0, 1_000_000)))
    envs.sort(key=event_time)
    return envs
