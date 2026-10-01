"""Event correlation, pattern detection, and anomaly alerting.

Provides three collaborating pieces:

* :class:`EventWindow` — bounded sliding window of events with filtering.
* :class:`CorrelationEngine` — rule-based event correlation across domains.
* :class:`PatternDetector` — sequence pattern matching over event streams.
* :class:`AnomalyDetector` — statistical anomaly detection on event rates.

All classes are dependency-light (stdlib only).
"""

from __future__ import annotations

import enum
import math
import statistics
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .event_bus import Domain, Event


class Severity(enum.Enum):
    """Alert severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class EventWindow:
    """Bounded sliding window of events with filtering capabilities."""

    max_size: int = 1000
    _events: deque = field(default_factory=deque, repr=False)

    def add(self, event: Event) -> None:
        """Add an event, evicting oldest if at capacity."""
        self._events.append(event)
        while len(self._events) > self.max_size:
            self._events.popleft()

    @property
    def size(self) -> int:
        return len(self._events)

    @property
    def events(self) -> List[Event]:
        return list(self._events)

    def filter(
        self,
        *,
        event_type: Optional[str] = None,
        domain: Optional[Domain] = None,
        entity_ref: Optional[str] = None,
    ) -> List[Event]:
        """Filter events by type, domain, and/or entity reference."""
        result = list(self._events)
        if event_type is not None:
            result = [e for e in result if e.event_type == event_type]
        if domain is not None:
            result = [e for e in result if e.source_domain == domain]
        if entity_ref is not None:
            result = [e for e in result if entity_ref in e.entity_refs]
        return result

    def clear(self) -> None:
        self._events.clear()


@dataclass
class CorrelationRule:
    """A rule for correlating events across domains."""

    name: str
    event_types: Set[str]
    time_window_seconds: float
    min_occurrences: int
    domains: Optional[Set[Domain]] = None
    entity_refs: Optional[Set[str]] = None


@dataclass
class CorrelationResult:
    """Result of a correlation rule match."""

    rule_name: str
    matching_events: List[Event]
    timestamp: float = 0.0


@dataclass
class PatternMatch:
    """A detected pattern match."""

    pattern: List[str]
    events: List[Event]


@dataclass
class AnomalyAlert:
    """An anomaly alert with severity and context."""

    value: float
    expected_range: Tuple[float, float]
    severity: Severity
    timestamp: float = 0.0
    message: str = ""


class CorrelationEngine:
    """Rule-based event correlation across domains."""

    def __init__(self) -> None:
        self.rules: Dict[str, CorrelationRule] = {}
        self._windows: Dict[str, EventWindow] = {}

    def add_rule(self, rule: CorrelationRule) -> None:
        self.rules[rule.name] = rule
        self._windows[rule.name] = EventWindow()

    def remove_rule(self, name: str) -> bool:
        if name in self.rules:
            del self.rules[name]
            del self._windows[name]
            return True
        return False

    def process_event(self, event: Event) -> List[CorrelationResult]:
        """Process an event against all rules, returning matches."""
        results: List[CorrelationResult] = []
        for name, rule in self.rules.items():
            if not self._rule_applies(rule, event):
                continue
            window = self._windows[name]
            window.add(event)
            matching = window.filter(event_type=event.event_type)
            if rule.domains is not None:
                matching = [e for e in matching if e.source_domain in rule.domains]
            if rule.entity_refs is not None:
                matching = [
                    e for e in matching
                    if any(ref in rule.entity_refs for ref in e.entity_refs)
                ]
            if len(matching) >= rule.min_occurrences:
                results.append(
                    CorrelationResult(
                        rule_name=name,
                        matching_events=matching,
                    )
                )
        return results

    def clear(self) -> None:
        self.rules.clear()
        self._windows.clear()

    @staticmethod
    def _rule_applies(rule: CorrelationRule, event: Event) -> bool:
        if event.event_type not in rule.event_types:
            return False
        if rule.domains is not None and event.source_domain not in rule.domains:
            return False
        if rule.entity_refs is not None:
            if not any(ref in rule.entity_refs for ref in event.entity_refs):
                return False
        return True


class PatternDetector:
    """Sequence pattern matching over event streams."""

    def __init__(self) -> None:
        self._patterns: List[Tuple[List[str], int]] = []
        self._buffer: List[Event] = []

    def add_pattern(self, sequence: List[str], max_gap: int = 0) -> None:
        self._patterns.append((sequence, max_gap))

    def remove_pattern(self, sequence: List[str]) -> bool:
        for i, (seq, _) in enumerate(self._patterns):
            if seq == sequence:
                self._patterns.pop(i)
                return True
        return False

    def process_event(self, event: Event) -> List[PatternMatch]:
        """Process an event and return any completed pattern matches."""
        self._buffer.append(event)
        matches: List[PatternMatch] = []
        for sequence, max_gap in self._patterns:
            match = self._try_match(sequence, max_gap)
            if match is not None:
                matches.append(match)
        return matches

    def clear(self) -> None:
        self._buffer.clear()

    def _try_match(
        self, sequence: List[str], max_gap: int
    ) -> Optional[PatternMatch]:
        """Try to find the pattern as a subsequence in the buffer."""
        if len(self._buffer) < len(sequence):
            return None
        # Search for the pattern as a subsequence
        match_indices = self._find_subsequence(sequence)
        if match_indices is None:
            return None
        # Check gap constraint
        if max_gap > 0:
            gap = match_indices[-1] - match_indices[0] - len(sequence) + 1
            if gap > max_gap:
                return None
        events = [self._buffer[i] for i in match_indices]
        return PatternMatch(pattern=list(sequence), events=events)

    def _find_subsequence(self, sequence: List[str]) -> Optional[List[int]]:
        """Find indices in buffer matching the sequence as a subsequence."""
        buf_types = [e.event_type for e in self._buffer]
        indices: List[int] = []
        seq_idx = 0
        for i, etype in enumerate(buf_types):
            if etype == sequence[seq_idx]:
                indices.append(i)
                seq_idx += 1
                if seq_idx == len(sequence):
                    return indices
        return None


class AnomalyDetector:
    """Statistical anomaly detection on event rates."""

    def __init__(
        self,
        window_size: int = 100,
        threshold_std: float = 3.0,
        min_samples: int = 5,
    ) -> None:
        self._window_size = window_size
        self._threshold_std = threshold_std
        self._min_samples = min_samples
        self._samples: deque = deque(maxlen=window_size)

    @property
    def baseline_mean(self) -> Optional[float]:
        if len(self._samples) < self._min_samples:
            return None
        return statistics.mean(self._samples)

    @property
    def baseline_std(self) -> Optional[float]:
        if len(self._samples) < self._min_samples:
            return None
        if len(self._samples) < 2:
            return 0.0
        return statistics.stdev(self._samples)

    def add_sample(self, value: float) -> None:
        self._samples.append(value)

    def check_value(self, value: float) -> Optional[AnomalyAlert]:
        """Check if a value is anomalous against the baseline."""
        mean = self.baseline_mean
        std = self.baseline_std
        if mean is None or std is None:
            return None
        if std == 0.0:
            return self._check_zero_std(value, mean)
        z_score = abs(value - mean) / std
        if z_score < self._threshold_std:
            return None
        severity = self._severity_for_zscore(z_score)
        return AnomalyAlert(
            value=value,
            expected_range=(
                mean - self._threshold_std * std,
                mean + self._threshold_std * std,
            ),
            severity=severity,
            message=(
                f"Anomaly detected: value={value}, "
                f"expected range=[{mean - self._threshold_std * std:.2f}, "
                f"{mean + self._threshold_std * std:.2f}], z_score={z_score:.2f}"
            ),
        )

    def _check_zero_std(self, value: float, mean: float) -> Optional[AnomalyAlert]:
        """Handle the case where all baseline samples are identical."""
        if mean == 0.0:
            deviation = abs(value)
        else:
            deviation = abs(value - mean) / abs(mean)
        if deviation < 0.30:
            return None
        severity = self._severity_for_deviation(deviation)
        return AnomalyAlert(
            value=value,
            expected_range=(mean, mean),
            severity=severity,
            message=f"Value {value} deviates from constant baseline {mean}",
        )

    def _severity_for_deviation(self, deviation: float) -> Severity:
        if deviation >= 10.0:
            return Severity.CRITICAL
        if deviation >= 1.0:
            return Severity.HIGH
        if deviation >= 0.30:
            return Severity.MEDIUM
        return Severity.LOW

    def clear(self) -> None:
        self._samples.clear()

    def _severity_for_zscore(self, z_score: float) -> Severity:
        if z_score >= 5.0:
            return Severity.CRITICAL
        if z_score >= 4.0:
            return Severity.HIGH
        if z_score >= 3.0:
            return Severity.MEDIUM
        return Severity.LOW
