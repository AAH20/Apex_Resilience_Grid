"""Tests for real-time simulation, what-if analysis, and predictive modeling."""
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from grid.digital_twin import (
    InfrastructureNode,
    InfrastructureEdge,
    DigitalTwin,
    NodeState,
)
from grid.simulation import (
    RealTimeSimulator,
    WhatIfAnalyzer,
    PredictiveModel,
    SimulationEvent,
    ScenarioConfig,
    TrendDirection,
)


# ── RealTimeSimulator tests ──

class TestRealTimeSimulator:
    def test_simulator_creation(self):
        twin = DigitalTwin()
        sim = RealTimeSimulator(twin)
        assert sim.twin is twin
        assert sim.current_time == 0.0
        assert sim.is_running is False

    def test_simulator_start_stop(self):
        twin = DigitalTwin()
        sim = RealTimeSimulator(twin)
        sim.start()
        assert sim.is_running is True
        sim.stop()
        assert sim.is_running is False

    def test_simulator_step_advances_time(self):
        twin = DigitalTwin()
        sim = RealTimeSimulator(twin, dt=0.5)
        sim.start()
        sim.step()
        assert sim.current_time == pytest.approx(0.5)
        sim.step()
        assert sim.current_time == pytest.approx(1.0)

    def test_simulator_step_without_start_raises(self):
        twin = DigitalTwin()
        sim = RealTimeSimulator(twin)
        with pytest.raises(RuntimeError):
            sim.step()

    def test_simulator_run_steps(self):
        twin = DigitalTwin()
        sim = RealTimeSimulator(twin, dt=1.0)
        sim.run(steps=5)
        assert sim.current_time == pytest.approx(5.0)

    def test_simulator_health_degradation_over_time(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0, current_load=95.0, health=0.8))
        sim = RealTimeSimulator(twin, dt=1.0, degradation_rate=0.05)
        sim.run(steps=3)
        # Health should degrade due to high load
        assert twin.nodes["n1"].health < 0.8

    def test_simulator_no_degradation_under_low_load(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0, current_load=20.0, health=1.0))
        sim = RealTimeSimulator(twin, dt=1.0, degradation_rate=0.05)
        sim.run(steps=5)
        assert twin.nodes["n1"].health == pytest.approx(1.0)

    def test_simulator_failure_event_emitted(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0, current_load=150.0, health=0.1))
        sim = RealTimeSimulator(twin, dt=1.0, degradation_rate=0.1)
        events = []
        sim.register_callback(lambda e: events.append(e))
        sim.run(steps=10)
        failure_events = [e for e in events if e.event_type == "failure"]
        assert len(failure_events) > 0

    def test_simulator_load_propagation(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="gen", node_type="power_plant", capacity=100.0, current_load=70.0))
        twin.add_node(InfrastructureNode(id="sub", node_type="substation", capacity=80.0, current_load=30.0))
        twin.add_edge(InfrastructureEdge(source="gen", target="sub", weight=1.0))
        sim = RealTimeSimulator(twin, dt=1.0, load_propagation_factor=0.3)
        sim.run(steps=3)
        # Load should propagate from gen to sub
        assert twin.nodes["sub"].current_load > 30.0

    def test_simulator_reset(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0, current_load=50.0))
        sim = RealTimeSimulator(twin, dt=1.0)
        sim.run(steps=5)
        sim.reset()
        assert sim.current_time == 0.0
        assert sim.is_running is False

    def test_simulator_snapshot_restore(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0, current_load=50.0))
        sim = RealTimeSimulator(twin, dt=1.0)
        sim.run(steps=3)
        snapshot = sim.snapshot_state()
        sim.run(steps=5)
        sim.restore_state(snapshot)
        assert sim.current_time == pytest.approx(3.0)

    def test_simulator_multiple_callbacks(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0, current_load=150.0, health=0.05))
        sim = RealTimeSimulator(twin, dt=1.0, degradation_rate=0.1)
        events1 = []
        events2 = []
        sim.register_callback(lambda e: events1.append(e))
        sim.register_callback(lambda e: events2.append(e))
        sim.run(steps=5)
        assert len(events1) == len(events2)


# ── WhatIfAnalyzer tests ──

class TestWhatIfAnalyzer:
    def test_analyzer_creation(self):
        twin = DigitalTwin()
        analyzer = WhatIfAnalyzer(twin)
        assert analyzer.twin is twin

    def test_whatif_load_increase(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0, current_load=50.0))
        analyzer = WhatIfAnalyzer(twin)
        result = analyzer.simulate_load_increase("n1", 30.0)
        assert result["new_load"] == pytest.approx(80.0)
        assert result["would_overload"] is False

    def test_whatif_load_increase_overload(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0, current_load=80.0))
        analyzer = WhatIfAnalyzer(twin)
        result = analyzer.simulate_load_increase("n1", 30.0)
        assert result["would_overload"] is True
        assert result["overload_amount"] == pytest.approx(10.0)

    def test_whatif_node_failure_impact(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="gen", node_type="power_plant", capacity=100.0, current_load=80.0))
        twin.add_node(InfrastructureNode(id="sub", node_type="substation", capacity=80.0, current_load=60.0))
        twin.add_node(InfrastructureNode(id="load", node_type="load", capacity=50.0, current_load=40.0))
        twin.add_edge(InfrastructureEdge(source="gen", target="sub", weight=1.0))
        twin.add_edge(InfrastructureEdge(source="sub", target="load", weight=1.0))
        analyzer = WhatIfAnalyzer(twin)
        result = analyzer.simulate_node_failure("gen")
        assert "gen" in result["failed_nodes"]
        assert result["total_failed"] >= 1

    def test_whatif_capacity_reduction(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0, current_load=80.0))
        analyzer = WhatIfAnalyzer(twin)
        result = analyzer.simulate_capacity_reduction("n1", 0.5)
        assert result["new_capacity"] == pytest.approx(50.0)
        assert result["would_overload"] is True

    def test_whatif_scenario_comparison(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0, current_load=50.0))
        analyzer = WhatIfAnalyzer(twin)
        scenarios = [
            ScenarioConfig(name="base", load_changes={"n1": 10.0}),
            ScenarioConfig(name="stress", load_changes={"n1": 60.0}),
        ]
        results = analyzer.compare_scenarios(scenarios)
        assert len(results) == 2
        assert results[0]["scenario_name"] == "base"
        assert results[1]["scenario_name"] == "stress"

    def test_whatif_sensitivity_analysis(self):
        twin = DigitalTwin()
        twin.add_node(InfrastructureNode(id="n1", node_type="power_plant", capacity=100.0, current_load=50.0))
        analyzer = WhatIfAnalyzer(twin)
        result = analyzer.sensitivity_analysis("n1", "load", [10.0, 20.0, 30.0])
        assert len(result) == 3
        # Higher load increase should yield higher new_load
        assert result[0]["new_load"] < result[1]["new_load"] < result[2]["new_load"]

    def test_whatif_nonexistent_node_raises(self):
        twin = DigitalTwin()
        analyzer = WhatIfAnalyzer(twin)
        with pytest.raises(KeyError):
            analyzer.simulate_load_increase("nonexistent", 10.0)


# ── PredictiveModel tests ──

class TestPredictiveModel:
    def test_model_creation(self):
        model = PredictiveModel()
        assert model.history_window == 10

    def test_record_observation(self):
        model = PredictiveModel()
        model.record_observation("n1", load=50.0, health=0.9)
        assert len(model.observations["n1"]) == 1

    def test_trend_analysis_increasing(self):
        model = PredictiveModel()
        for i in range(5):
            model.record_observation("n1", load=50.0 + i * 10, health=1.0)
        trend = model.analyze_trend("n1", "load")
        assert trend["direction"] == TrendDirection.INCREASING
        assert trend["slope"] > 0

    def test_trend_analysis_decreasing(self):
        model = PredictiveModel()
        for i in range(5):
            model.record_observation("n1", load=100.0 - i * 10, health=1.0)
        trend = model.analyze_trend("n1", "load")
        assert trend["direction"] == TrendDirection.DECREASING
        assert trend["slope"] < 0

    def test_trend_analysis_stable(self):
        model = PredictiveModel()
        for i in range(5):
            model.record_observation("n1", load=50.0, health=1.0)
        trend = model.analyze_trend("n1", "load")
        assert trend["direction"] == TrendDirection.STABLE

    def test_forecast_future_load(self):
        model = PredictiveModel()
        for i in range(5):
            model.record_observation("n1", load=50.0 + i * 10, health=1.0)
        forecast = model.forecast("n1", "load", steps=3)
        assert len(forecast) == 3
        # Forecast should continue increasing trend
        assert forecast[-1] > forecast[0]

    def test_forecast_insufficient_data(self):
        model = PredictiveModel()
        model.record_observation("n1", load=50.0, health=1.0)
        with pytest.raises(ValueError, match="Insufficient data"):
            model.forecast("n1", "load", steps=3)

    def test_predict_failure_probability(self):
        model = PredictiveModel()
        for i in range(5):
            model.record_observation("n1", load=90.0 + i * 2, health=0.5 - i * 0.05)
        prob = model.predict_failure_probability("n1")
        assert 0.0 <= prob <= 1.0
        assert prob > 0.5  # High load + declining health

    def test_detect_anomaly(self):
        model = PredictiveModel()
        for i in range(10):
            model.record_observation("n1", load=50.0, health=1.0)
        # Anomalous observation
        is_anomaly = model.detect_anomaly("n1", load=200.0, threshold=2.0)
        assert is_anomaly is True

    def test_detect_no_anomaly(self):
        model = PredictiveModel()
        for i in range(10):
            model.record_observation("n1", load=50.0, health=1.0)
        is_anomaly = model.detect_anomaly("n1", load=52.0, threshold=2.0)
        assert is_anomaly is False

    def test_health_forecast(self):
        model = PredictiveModel()
        for i in range(5):
            model.record_observation("n1", load=80.0, health=1.0 - i * 0.1)
        forecast = model.forecast("n1", "health", steps=3)
        assert len(forecast) == 3
        # Health should continue declining
        assert forecast[-1] < forecast[0]

    def test_observations_capped_at_window(self):
        model = PredictiveModel(history_window=5)
        for i in range(10):
            model.record_observation("n1", load=float(i), health=1.0)
        assert len(model.observations["n1"]) == 5

    def test_nonexistent_node_trend_raises(self):
        model = PredictiveModel()
        with pytest.raises(KeyError):
            model.analyze_trend("nonexistent", "load")
