#!/usr/bin/env python3
"""
Apex Resilience Grid — Digital Twin Demo
========================================

Demonstrates the digital twin capability of the Apex Resilience Grid.
Creates a virtual replica of a physical infrastructure (a small power
distribution network), synchronizes state from simulated sensors, runs
what-if scenarios, and visualizes the twin's understanding of the
physical system.

Usage:
    python3 demo_digital_twin.py
"""

from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class SensorReading:
    """A single sensor reading from the physical infrastructure."""
    sensor_id: str
    metric: str
    value: float
    unit: str
    timestamp: float


@dataclass
class PhysicalAsset:
    """A physical asset (transformer, switch, feeder, etc.)."""
    asset_id: str
    asset_type: str
    location: str
    rated_capacity: float
    current_load: float
    health_score: float  # 0–100
    status: str  # "normal", "warning", "critical", "offline"
    sensors: List[str] = field(default_factory=list)


@dataclass
class DigitalTwin:
    """The digital twin: a virtual replica of the physical grid."""
    twin_id: str
    name: str
    assets: Dict[str, PhysicalAsset] = field(default_factory=dict)
    sensor_history: Dict[str, List[SensorReading]] = field(default_factory=dict)
    last_sync: float = 0.0
    sync_count: int = 0

    def register_asset(self, asset: PhysicalAsset) -> None:
        self.assets[asset.asset_id] = asset

    def sync_from_physical(self, readings: List[SensorReading]) -> None:
        """Update the twin's state from physical sensor readings."""
        for reading in readings:
            # Store in history
            if reading.sensor_id not in self.sensor_history:
                self.sensor_history[reading.sensor_id] = []
            self.sensor_history[reading.sensor_id].append(reading)

            # Update the corresponding asset
            for asset in self.assets.values():
                if reading.sensor_id in asset.sensors:
                    if reading.metric == "load":
                        asset.current_load = reading.value
                    elif reading.metric == "health":
                        asset.health_score = reading.value
                    elif reading.metric == "status":
                        asset.status = str(reading.value)

        self.last_sync = time.time()
        self.sync_count += 1

    def get_asset_utilization(self, asset_id: str) -> float:
        """Return the utilization ratio (0–1) for an asset."""
        asset = self.assets.get(asset_id)
        if asset is None or asset.rated_capacity == 0:
            return 0.0
        return asset.current_load / asset.rated_capacity

    def get_overloaded_assets(self, threshold: float = 0.85) -> List[str]:
        """Return asset IDs whose utilization exceeds *threshold*."""
        return [
            aid for aid, asset in self.assets.items()
            if self.get_asset_utilization(aid) > threshold
        ]

    def run_what_if(self, asset_id: str, load_delta: float) -> dict:
        """
        Run a what-if scenario: what happens if *asset_id*'s load changes
        by *load_delta* MW?
        """
        asset = self.assets.get(asset_id)
        if asset is None:
            return {"error": f"Asset {asset_id} not found"}

        new_load = asset.current_load + load_delta
        new_util = new_load / asset.rated_capacity if asset.rated_capacity > 0 else 0

        if new_util > 1.0:
            projected_status = "critical"
            recommendation = f"REJECT: would overload {asset_id} to {new_util*100:.0f}% — shed {new_load - asset.rated_capacity:.0f} MW"
        elif new_util > 0.85:
            projected_status = "warning"
            recommendation = f"CAUTION: {asset_id} would reach {new_util*100:.0f}% — consider load transfer"
        else:
            projected_status = "normal"
            recommendation = f"OK: {asset_id} would operate at {new_util*100:.0f}%"

        return {
            "asset_id": asset_id,
            "current_load_mw": asset.current_load,
            "load_delta_mw": load_delta,
            "projected_load_mw": new_load,
            "projected_utilization": round(new_util, 3),
            "projected_status": projected_status,
            "recommendation": recommendation,
        }


# ---------------------------------------------------------------------------
# Sample infrastructure
# ---------------------------------------------------------------------------

def build_sample_infrastructure() -> DigitalTwin:
    """Build a sample digital twin of a power distribution network."""
    twin = DigitalTwin(
        twin_id="TWIN-001",
        name="Downtown Distribution Network Twin",
    )

    assets = [
        PhysicalAsset(
            asset_id="TX-01", asset_type="Transformer", location="Substation A",
            rated_capacity=100, current_load=72, health_score=88, status="normal",
            sensors=["S-TX01-LOAD", "S-TX01-HEALTH"],
        ),
        PhysicalAsset(
            asset_id="TX-02", asset_type="Transformer", location="Substation B",
            rated_capacity=80, current_load=55, health_score=92, status="normal",
            sensors=["S-TX02-LOAD", "S-TX02-HEALTH"],
        ),
        PhysicalAsset(
            asset_id="FDR-01", asset_type="Feeder", location="Main Street",
            rated_capacity=60, current_load=51, health_score=76, status="warning",
            sensors=["S-FDR01-LOAD", "S-FDR01-HEALTH"],
        ),
        PhysicalAsset(
            asset_id="FDR-02", asset_type="Feeder", location="Industrial Ave",
            rated_capacity=50, current_load=22, health_score=95, status="normal",
            sensors=["S-FDR02-LOAD", "S-FDR02-HEALTH"],
        ),
        PhysicalAsset(
            asset_id="SW-01", asset_type="Switch", location="Junction 7",
            rated_capacity=200, current_load=130, health_score=81, status="normal",
            sensors=["S-SW01-LOAD", "S-SW01-HEALTH"],
        ),
        PhysicalAsset(
            asset_id="GEN-01", asset_type="Generator", location="Backup Plant",
            rated_capacity=40, current_load=0, health_score=97, status="offline",
            sensors=["S-GEN01-LOAD", "S-GEN01-HEALTH"],
        ),
    ]

    for asset in assets:
        twin.register_asset(asset)

    return twin


# ---------------------------------------------------------------------------
# Simulated sensor feed
# ---------------------------------------------------------------------------

def generate_sensor_readings(twin: DigitalTwin) -> List[SensorReading]:
    """Generate simulated sensor readings for all assets in the twin."""
    readings: List[SensorReading] = []
    now = time.time()

    for asset in twin.assets.values():
        for sensor_id in asset.sensors:
            if "LOAD" in sensor_id:
                # Simulate load with small random variation
                base_load = asset.current_load
                variation = random.uniform(-3, 3)
                value = max(0, base_load + variation)
                readings.append(SensorReading(sensor_id, "load", round(value, 1), "MW", now))
            elif "HEALTH" in sensor_id:
                # Health degrades slowly
                base_health = asset.health_score
                variation = random.uniform(-0.5, 0.1)
                value = max(0, min(100, base_health + variation))
                readings.append(SensorReading(sensor_id, "health", round(value, 1), "%", now))

    return readings


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_twin_state(twin: DigitalTwin) -> None:
    """Print the current state of the digital twin."""
    print(f"\n  Digital Twin: {twin.name} ({twin.twin_id})")
    print(f"  Sync count: {twin.sync_count} | Last sync: {time.strftime('%H:%M:%S', time.localtime(twin.last_sync))}")
    print(f"\n  {'Asset':<10} {'Type':<14} {'Location':<20} {'Load':>8} {'Capacity':>8} {'Util':>6} {'Health':>6} {'Status':<10}")
    print(f"  {'-'*10} {'-'*14} {'-'*20} {'-'*8} {'-'*8} {'-'*6} {'-'*6} {'-'*10}")

    for asset in twin.assets.values():
        util = twin.get_asset_utilization(asset.asset_id) * 100
        print(
            f"  {asset.asset_id:<10} {asset.asset_type:<14} {asset.location:<20} "
            f"{asset.current_load:>6.1f}MW {asset.rated_capacity:>6.0f}MW "
            f"{util:>5.1f}% {asset.health_score:>5.1f}% {asset.status:<10}"
        )


def print_what_if_results(results: List[dict]) -> None:
    """Print what-if scenario results."""
    print(f"\n  {'Asset':<10} {'Delta MW':>10} {'Proj Load':>10} {'Util':>6} {'Status':<10} {'Recommendation'}")
    print(f"  {'-'*10} {'-'*10} {'-'*10} {'-'*6} {'-'*10} {'-'*50}")
    for r in results:
        if "error" in r:
            print(f"  {r['error']}")
            continue
        print(
            f"  {r['asset_id']:<10} {r['load_delta_mw']:>+8.1f}MW {r['projected_load_mw']:>8.1f}MW "
            f"{r['projected_utilization']*100:>5.1f}% {r['projected_status']:<10} {r['recommendation']}"
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 70)
    print("  APEX RESILIENCE GRID — Digital Twin Demo")
    print("=" * 70)

    # Build the digital twin
    twin = build_sample_infrastructure()

    print("\n[1] Digital twin created with sample infrastructure:")
    print_twin_state(twin)

    # Simulate sensor synchronization cycles
    print("\n[2] Simulating sensor synchronization (3 cycles)...")
    for cycle in range(1, 4):
        readings = generate_sensor_readings(twin)
        twin.sync_from_physical(readings)
        print(f"    Cycle {cycle}: {len(readings)} sensor readings ingested")

    print("\n[3] Twin state after synchronization:")
    print_twin_state(twin)

    # Check for overloaded assets
    overloaded = twin.get_overloaded_assets(threshold=0.80)
    print(f"\n[4] Overloaded assets (utilization > 80%): {', '.join(overloaded) or 'none'}")

    # Run what-if scenarios
    print("\n[5] Running what-if scenarios:")
    scenarios: List[Tuple[str, float]] = [
        ("TX-01", 20),    # Add 20 MW to Transformer 1
        ("FDR-01", 15),   # Add 15 MW to Feeder 1 (already near capacity)
        ("TX-02", -10),   # Remove 10 MW from Transformer 2
        ("FDR-02", 35),   # Add 35 MW to Feeder 2
        ("GEN-01", 30),   # Start backup generator
    ]

    results = []
    for asset_id, delta in scenarios:
        result = twin.run_what_if(asset_id, delta)
        results.append(result)

    print_what_if_results(results)

    # Sensor history summary
    print("\n[6] Sensor history summary:")
    for sensor_id, history in twin.sensor_history.items():
        if history:
            latest = history[-1]
            print(f"    {sensor_id}: {len(history)} readings, latest = {latest.value} {latest.unit}")

    # JSON export
    output = {
        "twin_id": twin.twin_id,
        "twin_name": twin.name,
        "sync_count": twin.sync_count,
        "assets": {
            aid: {
                "type": a.asset_type,
                "location": a.location,
                "load_mw": a.current_load,
                "capacity_mw": a.rated_capacity,
                "utilization": round(twin.get_asset_utilization(aid), 3),
                "health": a.health_score,
                "status": a.status,
            }
            for aid, a in twin.assets.items()
        },
        "overloaded_assets": overloaded,
        "what_if_results": results,
    }
    print(f"\n[7] JSON export:")
    print(json.dumps(output, indent=2))
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
