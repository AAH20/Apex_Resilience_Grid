#!/usr/bin/env python3
"""
Apex Resilience Grid — Self-Healing Demo
========================================

Demonstrates the self-healing capability of the Apex Resilience Grid.
Simulates a series of faults (line trips, generator outages, load spikes)
and shows how the grid automatically detects, isolates, and recovers
from each fault using predefined healing policies.

Usage:
    python3 demo_self_healing.py
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enums and data model
# ---------------------------------------------------------------------------

class FaultType(Enum):
    LINE_TRIP = "line_trip"
    GENERATOR_OUTAGE = "generator_outage"
    LOAD_SPIKE = "load_spike"
    BUS_FAULT = "bus_fault"


class HealingAction(Enum):
    REROUTE = "reroute_power"
    SHED_LOAD = "shed_non_critical_load"
    START_BACKUP = "start_backup_generator"
    ISOLATE = "isolate_faulty_section"
    RECONNECT = "reconnect_after_clear"


@dataclass
class Fault:
    """A fault event in the grid."""
    id: str
    fault_type: FaultType
    target_id: str
    severity: int  # 1 (minor) to 5 (critical)
    description: str


@dataclass
class HealingResult:
    """Result of a healing action."""
    fault_id: str
    action: HealingAction
    success: bool
    message: str
    timestamp: float = 0.0


@dataclass
class GridState:
    """Simplified grid state for self-healing demo."""
    buses: Dict[str, dict] = field(default_factory=dict)
    lines: Dict[str, dict] = field(default_factory=dict)
    generators: Dict[str, dict] = field(default_factory=dict)
    backup_generators: Dict[str, dict] = field(default_factory=dict)
    load_shed_count: int = 0
    total_recovered: int = 0


# ---------------------------------------------------------------------------
# Sample grid
# ---------------------------------------------------------------------------

def build_sample_grid() -> GridState:
    """Build a sample grid with generators, buses, and lines."""
    state = GridState()

    # Primary generators
    state.generators = {
        "G1": {"name": "North Generator", "capacity_mw": 200, "output_mw": 180, "online": True},
        "G2": {"name": "South Generator", "capacity_mw": 150, "output_mw": 120, "online": True},
    }

    # Backup generators (offline by default)
    state.backup_generators = {
        "BG1": {"name": "Backup Gen A", "capacity_mw": 80, "output_mw": 0, "online": False},
        "BG2": {"name": "Backup Gen B", "capacity_mw": 60, "output_mw": 0, "online": False},
    }

    # Buses
    state.buses = {
        "B1": {"name": "East Substation", "load_mw": 80, "critical": True, "online": True},
        "B2": {"name": "Central Hub", "load_mw": 120, "critical": True, "online": True},
        "B3": {"name": "West Substation", "load_mw": 60, "critical": False, "online": True},
        "B4": {"name": "Industrial Park", "load_mw": 90, "critical": False, "online": True},
        "B5": {"name": "Residential", "load_mw": 50, "critical": False, "online": True},
    }

    # Lines
    state.lines = {
        "L1": {"from": "G1", "to": "B1", "capacity_mw": 150, "online": True},
        "L2": {"from": "B1", "to": "B2", "capacity_mw": 100, "online": True},
        "L3": {"from": "G2", "to": "B2", "capacity_mw": 120, "online": True},
        "L4": {"from": "B2", "to": "B4", "capacity_mw": 80, "online": True},
        "L5": {"from": "B3", "to": "B4", "capacity_mw": 70, "online": True},
        "L6": {"from": "B4", "to": "B5", "capacity_mw": 60, "online": True},
    }

    return state


# ---------------------------------------------------------------------------
# Healing policies
# ---------------------------------------------------------------------------

def heal_line_trip(state: GridState, fault: Fault) -> HealingResult:
    """Heal a line trip by rerouting power through alternate paths."""
    line = state.lines.get(fault.target_id)
    if line is None:
        return HealingResult(fault.id, HealingAction.REROUTE, False, f"Line {fault.target_id} not found")

    if not line["online"]:
        return HealingResult(fault.id, HealingAction.REROUTE, False, f"Line {fault.target_id} already offline")

    # Isolate the faulty line
    line["online"] = False

    # Try to reroute: find alternate path (simplified)
    # In a real system this would use a power-flow solver
    alt_found = False
    for lid, l in state.lines.items():
        if lid != fault.target_id and l["online"]:
            # Simplified: assume we can reroute if any other line exists
            alt_found = True
            break

    if alt_found:
        state.total_recovered += 1
        return HealingResult(
            fault.id, HealingAction.REROUTE, True,
            f"Line {fault.target_id} isolated; power rerouted via alternate path"
        )
    else:
        return HealingResult(
            fault.id, HealingAction.REROUTE, False,
            f"Line {fault.target_id} isolated; no alternate path available"
        )


def heal_generator_outage(state: GridState, fault: Fault) -> HealingResult:
    """Heal a generator outage by starting a backup generator."""
    gen = state.generators.get(fault.target_id)
    if gen is None:
        return HealingResult(fault.id, HealingAction.START_BACKUP, False, f"Generator {fault.target_id} not found")

    gen["online"] = False
    gen["output_mw"] = 0

    # Try to start a backup generator
    for bid, bg in state.backup_generators.items():
        if not bg["online"]:
            bg["online"] = True
            bg["output_mw"] = bg["capacity_mw"] * 0.8  # 80% output
            state.total_recovered += 1
            return HealingResult(
                fault.id, HealingAction.START_BACKUP, True,
                f"Generator {fault.target_id} lost; backup {bid} started at {bg['output_mw']:.0f} MW"
            )

    return HealingResult(
        fault.id, HealingAction.START_BACKUP, False,
        f"Generator {fault.target_id} lost; no backup available — load shedding required"
    )


def heal_load_spike(state: GridState, fault: Fault) -> HealingResult:
    """Heal a load spike by shedding non-critical load."""
    bus = state.buses.get(fault.target_id)
    if bus is None:
        return HealingResult(fault.id, HealingAction.SHED_LOAD, False, f"Bus {fault.target_id} not found")

    # Shed non-critical load
    shed_amount = 0
    for bid, b in state.buses.items():
        if not b["critical"] and b["online"] and b["load_mw"] > 0:
            shed = min(b["load_mw"], 30)  # shed up to 30 MW per bus
            b["load_mw"] -= shed
            shed_amount += shed
            state.load_shed_count += 1

    state.total_recovered += 1
    return HealingResult(
        fault.id, HealingAction.SHED_LOAD, True,
        f"Load spike at {fault.target_id}; shed {shed_amount:.0f} MW of non-critical load"
    )


def heal_bus_fault(state: GridState, fault: Fault) -> HealingResult:
    """Heal a bus fault by isolating the faulty section."""
    bus = state.buses.get(fault.target_id)
    if bus is None:
        return HealingResult(fault.id, HealingAction.ISOLATE, False, f"Bus {fault.target_id} not found")

    bus["online"] = False

    # Isolate connected lines
    isolated_lines = []
    for lid, l in state.lines.items():
        if (l["from"] == fault.target_id or l["to"] == fault.target_id) and l["online"]:
            l["online"] = False
            isolated_lines.append(lid)

    state.total_recovered += 1
    return HealingResult(
        fault.id, HealingAction.ISOLATE, True,
        f"Bus {fault.target_id} fault isolated; lines {', '.join(isolated_lines)} disconnected"
    )


# Healing dispatch table
HEALING_POLICIES: Dict[FaultType, Callable] = {
    FaultType.LINE_TRIP: heal_line_trip,
    FaultType.GENERATOR_OUTAGE: heal_generator_outage,
    FaultType.LOAD_SPIKE: heal_load_spike,
    FaultType.BUS_FAULT: heal_bus_fault,
}


# ---------------------------------------------------------------------------
# Simulation
# ---------------------------------------------------------------------------

def run_self_healing_demo() -> None:
    """Run the self-healing demonstration."""
    print("=" * 70)
    print("  APEX RESILIENCE GRID — Self-Healing Demo")
    print("=" * 70)

    state = build_sample_grid()

    # Print initial state
    print("\n[1] Initial Grid State:")
    print(f"    Generators online:   {sum(1 for g in state.generators.values() if g['online'])} / {len(state.generators)}")
    print(f"    Backup generators:   {sum(1 for g in state.backup_generators.values() if g['online'])} / {len(state.backup_generators)}")
    print(f"    Buses online:        {sum(1 for b in state.buses.values() if b['online'])} / {len(state.buses)}")
    print(f"    Lines online:        {sum(1 for l in state.lines.values() if l['online'])} / {len(state.lines)}")
    total_load = sum(b["load_mw"] for b in state.buses.values() if b["online"])
    total_gen = sum(g["output_mw"] for g in state.generators.values() if g["online"])
    total_bg = sum(g["output_mw"] for g in state.backup_generators.values() if g["online"])
    print(f"    Total load:          {total_load:.0f} MW")
    print(f"    Total generation:    {total_gen + total_bg:.0f} MW")

    # Define a sequence of faults
    faults = [
        Fault("F1", FaultType.LINE_TRIP, "L2", 3, "Lightning strike on trunk line L2"),
        Fault("F2", FaultType.GENERATOR_OUTAGE, "G1", 5, "North Generator trip — bearing failure"),
        Fault("F3", FaultType.LOAD_SPIKE, "B4", 2, "Industrial Park demand surge"),
        Fault("F4", FaultType.BUS_FAULT, "B3", 4, "Insulator breakdown at West Substation"),
    ]

    print(f"\n[2] Injecting {len(faults)} faults...")
    print("-" * 70)

    results: List[HealingResult] = []

    for fault in faults:
        print(f"\n  ⚡ FAULT {fault.id}: {fault.description}")
        print(f"     Type: {fault.fault_type.value} | Target: {fault.target_id} | Severity: {fault.severity}/5")

        # Dispatch to the appropriate healing policy
        handler = HEALING_POLICIES.get(fault.fault_type)
        if handler is None:
            print(f"     ❌ No healing policy for fault type {fault.fault_type.value}")
            continue

        result = handler(state, fault)
        result.timestamp = time.time()
        results.append(result)

        status = "✅ HEALED" if result.success else "⚠️  PARTIAL"
        print(f"     {status}: {result.message}")
        print(f"     Action: {result.action.value}")

    # Print final state
    print("\n" + "-" * 70)
    print("\n[3] Final Grid State After Self-Healing:")
    print(f"    Generators online:   {sum(1 for g in state.generators.values() if g['online'])} / {len(state.generators)}")
    print(f"    Backup generators:   {sum(1 for g in state.backup_generators.values() if g['online'])} / {len(state.backup_generators)}")
    print(f"    Buses online:        {sum(1 for b in state.buses.values() if b['online'])} / {len(state.buses)}")
    print(f"    Lines online:        {sum(1 for l in state.lines.values() if l['online'])} / {len(state.lines)}")
    total_load = sum(b["load_mw"] for b in state.buses.values() if b["online"])
    total_gen = sum(g["output_mw"] for g in state.generators.values() if g["online"])
    total_bg = sum(g["output_mw"] for g in state.backup_generators.values() if g["online"])
    print(f"    Total load:          {total_load:.0f} MW")
    print(f"    Total generation:    {total_gen + total_bg:.0f} MW")
    print(f"    Load shed events:    {state.load_shed_count}")
    print(f"    Faults recovered:    {state.total_recovered} / {len(faults)}")

    # Summary
    healed = sum(1 for r in results if r.success)
    print(f"\n  ── Self-Healing Summary ──")
    print(f"    Faults processed:    {len(results)}")
    print(f"    Fully healed:        {healed}")
    print(f"    Partially healed:    {len(results) - healed}")
    print(f"    Success rate:        {healed / len(results) * 100:.0f}%")

    # JSON export
    output = {
        "faults_injected": len(faults),
        "faults_healed": healed,
        "success_rate_pct": round(healed / len(results) * 100, 1),
        "load_shed_events": state.load_shed_count,
        "final_state": {
            "generators_online": sum(1 for g in state.generators.values() if g["online"]),
            "backup_generators_online": sum(1 for g in state.backup_generators.values() if g["online"]),
            "buses_online": sum(1 for b in state.buses.values() if b["online"]),
            "lines_online": sum(1 for l in state.lines.values() if l["online"]),
            "total_load_mw": total_load,
            "total_generation_mw": total_gen + total_bg,
        },
        "healing_actions": [
            {
                "fault_id": r.fault_id,
                "action": r.action.value,
                "success": r.success,
                "message": r.message,
            }
            for r in results
        ],
    }
    print(f"\n[4] JSON export:")
    print(json.dumps(output, indent=2))
    print("\n" + "=" * 70)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    run_self_healing_demo()
