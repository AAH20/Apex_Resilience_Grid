#!/usr/bin/env python3
"""
Apex Resilience Grid — Cascading Failure Analysis Demo
=====================================================

Demonstrates how a single component failure can propagate through a power
grid, causing downstream outages. Models a small 6-bus electrical grid,
simulates the loss of a critical transmission line, and traces the cascade.

Usage:
    python3 demo_cascading_failure.py
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Set


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Bus:
    """A node in the electrical grid (generator or load)."""
    id: str
    name: str
    capacity_mw: float
    load_mw: float
    is_generator: bool = False
    is_failed: bool = False


@dataclass
class Line:
    """A transmission line connecting two buses."""
    id: str
    from_bus: str
    to_bus: str
    capacity_mw: float
    is_failed: bool = False


@dataclass
class Grid:
    """The electrical grid: a collection of buses and lines."""
    buses: Dict[str, Bus] = field(default_factory=dict)
    lines: Dict[str, Line] = field(default_factory=dict)

    def add_bus(self, bus: Bus) -> None:
        self.buses[bus.id] = bus

    def add_line(self, line: Line) -> None:
        self.lines[line.id] = line

    def total_load(self) -> float:
        return sum(b.load_mw for b in self.buses.values() if not b.is_generator)

    def total_capacity(self) -> float:
        return sum(b.capacity_mw for b in self.buses.values() if b.is_generator)


# ---------------------------------------------------------------------------
# Sample grid construction
# ---------------------------------------------------------------------------

def build_sample_grid() -> Grid:
    """
    Build a small 6-bus grid:

        G1 (Gen, 200 MW) ── L1 ── B2 (Load 80 MW)
                                     │
                                    L2
                                     │
        G2 (Gen, 150 MW) ── L3 ── B3 (Load 120 MW)
                                     │
                                    L4
                                     │
        B4 (Load 60 MW) ──── L5 ── B5 (Load 90 MW)
                                     │
                                    L6
                                     │
                              B6 (Load 50 MW)
    """
    grid = Grid()

    # Generators
    grid.add_bus(Bus("G1", "North Generator",  capacity_mw=200, load_mw=0,   is_generator=True))
    grid.add_bus(Bus("G2", "South Generator",  capacity_mw=150, load_mw=0,   is_generator=True))

    # Load buses
    grid.add_bus(Bus("B2", "East Substation",  capacity_mw=0,   load_mw=80))
    grid.add_bus(Bus("B3", "Central Hub",     capacity_mw=0,   load_mw=120))
    grid.add_bus(Bus("B4", "West Substation", capacity_mw=0,   load_mw=60))
    grid.add_bus(Bus("B5", "Industrial Park",  capacity_mw=0,   load_mw=90))
    grid.add_bus(Bus("B6", "Residential",     capacity_mw=0,   load_mw=50))

    # Transmission lines
    grid.add_line(Line("L1", "G1", "B2", capacity_mw=150))
    grid.add_line(Line("L2", "B2", "B3", capacity_mw=100))
    grid.add_line(Line("L3", "G2", "B3", capacity_mw=120))
    grid.add_line(Line("L4", "B3", "B5", capacity_mw=80))
    grid.add_line(Line("L5", "B4", "B5", capacity_mw=70))
    grid.add_line(Line("L6", "B5", "B6", capacity_mw=60))

    return grid


# ---------------------------------------------------------------------------
# Cascading failure simulation
# ---------------------------------------------------------------------------

def simulate_cascade(grid: Grid, initial_line_id: str) -> List[dict]:
    """
    Simulate a cascading failure starting from the loss of *initial_line_id*.

    Algorithm:
        1. Mark the initial line as failed.
        2. Recompute power flow (simplified: proportional redistribution).
        3. Any line whose flow exceeds its capacity also fails.
        4. Repeat until no new failures occur.

    Returns a list of cascade steps (one dict per iteration).
    """
    steps: List[dict] = []
    failed_lines: Set[str] = set()
    failed_buses: Set[str] = set()

    # Step 0 — initial failure
    if initial_line_id not in grid.lines:
        raise ValueError(f"Unknown line: {initial_line_id}")

    grid.lines[initial_line_id].is_failed = True
    failed_lines.add(initial_line_id)

    steps.append({
        "step": 0,
        "event": f"Initial failure: line {initial_line_id} lost",
        "newly_failed_lines": [initial_line_id],
        "newly_failed_buses": [],
        "total_failed_lines": list(failed_lines),
        "total_failed_buses": list(failed_buses),
    })

    # Iterate until convergence
    iteration = 0
    max_iterations = 10

    while iteration < max_iterations:
        iteration += 1
        new_line_failures: List[str] = []
        new_bus_failures: List[str] = []

        # Simplified power-flow redistribution:
        # For each still-active line, check if the remaining generation can
        # still serve the connected loads.  If a bus loses all incoming
        # lines, it is islanded (failed).
        for line in grid.lines.values():
            if line.is_failed:
                continue

            # Check if either endpoint is already islanded
            if line.from_bus in failed_buses or line.to_bus in failed_buses:
                line.is_failed = True
                new_line_failures.append(line.id)
                failed_lines.add(line.id)
                continue

            # Simplified overload check: if total remaining generation
            # cannot cover total remaining load, the weakest line fails.
            remaining_gen = sum(
                b.capacity_mw for b in grid.buses.values()
                if b.is_generator and b.id not in failed_buses
            )
            remaining_load = sum(
                b.load_mw for b in grid.buses.values()
                if not b.is_generator and b.id not in failed_buses
            )

            if remaining_gen < remaining_load:
                # Overload — this line trips
                line.is_failed = True
                new_line_failures.append(line.id)
                failed_lines.add(line.id)

        # Check for islanded buses (all connected lines failed)
        for bus in grid.buses.values():
            if bus.is_generator or bus.id in failed_buses:
                continue
            connected_lines = [
                l for l in grid.lines.values()
                if (l.from_bus == bus.id or l.to_bus == bus.id) and not l.is_failed
            ]
            if not connected_lines and bus.load_mw > 0:
                bus.is_failed = True
                new_bus_failures.append(bus.id)
                failed_buses.add(bus.id)

        steps.append({
            "step": iteration,
            "event": f"Cascade iteration {iteration}",
            "newly_failed_lines": new_line_failures,
            "newly_failed_buses": new_bus_failures,
            "total_failed_lines": sorted(failed_lines),
            "total_failed_buses": sorted(failed_buses),
        })

        if not new_line_failures and not new_bus_failures:
            break

    return steps


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_grid_state(grid: Grid) -> None:
    """Print a human-readable snapshot of the grid."""
    print("\n  Buses:")
    print(f"    {'ID':<6} {'Name':<22} {'Type':<12} {'Capacity':>10} {'Load':>10}")
    print(f"    {'-'*6} {'-'*22} {'-'*12} {'-'*10} {'-'*10}")
    for bus in grid.buses.values():
        btype = "Generator" if bus.is_generator else "Load"
        cap = f"{bus.capacity_mw:.0f} MW" if bus.is_generator else "—"
        load = f"{bus.load_mw:.0f} MW" if not bus.is_generator else "—"
        status = " [FAILED]" if bus.is_failed else ""
        print(f"    {bus.id:<6} {bus.name:<22} {btype:<12} {cap:>10} {load:>10}{status}")

    print("\n  Lines:")
    print(f"    {'ID':<6} {'From':<6} {'To':<6} {'Capacity':>10} {'Status':<12}")
    print(f"    {'-'*6} {'-'*6} {'-'*6} {'-'*10} {'-'*12}")
    for line in grid.lines.values():
        status = "FAILED" if line.is_failed else "OK"
        print(f"    {line.id:<6} {line.from_bus:<6} {line.to_bus:<6} {line.capacity_mw:>8.0f} MW  {status:<12}")


def print_cascade_report(steps: List[dict]) -> None:
    """Print a formatted cascade report."""
    print("\n" + "=" * 70)
    print("  CASCADE FAILURE REPORT")
    print("=" * 70)

    for step in steps:
        print(f"\n  Step {step['step']}: {step['event']}")
        if step["newly_failed_lines"]:
            print(f"    New line failures:   {', '.join(step['newly_failed_lines'])}")
        if step["newly_failed_buses"]:
            print(f"    New bus failures:    {', '.join(step['newly_failed_buses'])}")
        print(f"    Cumulative lines:    {', '.join(step['total_failed_lines']) or 'none'}")
        print(f"    Cumulative buses:     {', '.join(step['total_failed_buses']) or 'none'}")

    # Summary
    final = steps[-1]
    print(f"\n  ── Summary ──")
    print(f"    Total steps:         {len(steps)}")
    print(f"    Lines failed:        {len(final['total_failed_lines'])} / 6")
    print(f"    Buses islanded:      {len(final['total_failed_buses'])} / 6")
    print("=" * 70)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 70)
    print("  APEX RESILIENCE GRID — Cascading Failure Analysis Demo")
    print("=" * 70)

    # Build the sample grid
    grid = build_sample_grid()

    print("\n[1] Initial grid state:")
    print_grid_state(grid)

    # Simulate cascading failure starting from loss of L2 (critical trunk line)
    initial_failure = "L2"
    print(f"\n[2] Simulating cascading failure from loss of line {initial_failure}...")

    steps = simulate_cascade(grid, initial_failure)

    print("\n[3] Final grid state after cascade:")
    print_grid_state(grid)

    print_cascade_report(steps)

    # Export results as JSON
    output = {
        "initial_failure": initial_failure,
        "cascade_steps": steps,
        "final_state": {
            "failed_lines": sorted(lid for lid, l in grid.lines.items() if l.is_failed),
            "failed_buses": sorted(bid for bid, b in grid.buses.items() if b.is_failed),
        },
    }
    print("\n[4] JSON export:")
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
