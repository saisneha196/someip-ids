"""
Tests for the feature extractor and detector (Stages 4-5).
"""

import json
import os
import sys
import tempfile

import numpy as np
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detector.feature_extractor import (
    compute_window_features,
    extract_windows,
    load_traffic_log,
    FEATURE_COLUMNS,
    _shannon_entropy,
)


# ======================================================================
# Feature Extraction Tests
# ======================================================================

class TestFeatureExtractor:
    """Tests for windowed feature computation."""

    def _make_record(self, service_id="0x1001", method_id="0x0001",
                      message_type="REQUEST", session_id="0x0001",
                      payload_size=8, label="normal", ts_offset=0.0):
        """Create a synthetic traffic record."""
        from datetime import datetime, timezone, timedelta
        ts = datetime(2026, 7, 23, 12, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=ts_offset)
        return {
            "timestamp": ts.isoformat(),
            "direction": "sent",
            "src_ip": "172.20.0.20",
            "dst_ip": "172.20.0.10",
            "service_id": service_id,
            "method_id": method_id,
            "client_id": "0x0010",
            "session_id": session_id,
            "message_type": message_type,
            "return_code": "0x00",
            "payload_size": payload_size,
            "payload_hex": "00" * payload_size,
            "label": label,
        }

    def test_empty_window(self):
        """Empty record list should produce zero features."""
        features = compute_window_features([], window_seconds=2.0)
        assert features["msg_count"] == 0
        assert features["msg_rate"] == 0.0

    def test_single_message(self):
        """Single message should produce count=1."""
        records = [self._make_record()]
        features = compute_window_features(records, window_seconds=2.0)
        assert features["msg_count"] == 1
        assert features["msg_rate"] == 0.5

    def test_multiple_services(self):
        """Messages from multiple services should be counted."""
        records = [
            self._make_record(service_id="0x1001"),
            self._make_record(service_id="0x2001"),
            self._make_record(service_id="0x3001"),
        ]
        features = compute_window_features(records, window_seconds=2.0)
        assert features["unique_services"] == 3

    def test_session_entropy(self):
        """Different session IDs should produce higher entropy."""
        # All same session
        records_same = [
            self._make_record(session_id="0x0001", ts_offset=i * 0.1)
            for i in range(10)
        ]
        feat_same = compute_window_features(records_same)

        # All different sessions
        records_diff = [
            self._make_record(session_id=f"0x{i:04X}", ts_offset=i * 0.1)
            for i in range(1, 11)
        ]
        feat_diff = compute_window_features(records_diff)

        assert feat_diff["session_id_entropy"] > feat_same["session_id_entropy"]

    def test_sd_offer_detection(self):
        """SD Offer messages should be counted."""
        records = [
            self._make_record(service_id="0xFFFF", method_id="0x8100",
                            message_type="NOTIFICATION"),
            self._make_record(service_id="0xFFFF", method_id="0x8100",
                            message_type="NOTIFICATION"),
            self._make_record(service_id="0x1001"),
        ]
        features = compute_window_features(records, window_seconds=2.0)
        assert features["sd_offer_count"] == 2
        assert features["sd_offer_rate"] == 1.0

    def test_payload_stats(self):
        """Payload size statistics should be computed correctly."""
        records = [
            self._make_record(payload_size=10),
            self._make_record(payload_size=20),
            self._make_record(payload_size=30),
        ]
        features = compute_window_features(records)
        assert features["mean_payload_size"] == 20.0
        assert features["std_payload_size"] > 0

    def test_feature_columns_complete(self):
        """All expected feature columns should be present in output."""
        records = [self._make_record()]
        features = compute_window_features(records)
        for col in FEATURE_COLUMNS:
            assert col in features, f"Missing feature: {col}"

    def test_extract_windows_labels(self):
        """Windows containing attack records should be labeled as attack."""
        records = []
        # 4 seconds of normal traffic
        for i in range(20):
            records.append(self._make_record(ts_offset=i * 0.2, label="normal"))
        # 2 seconds of attack traffic
        for i in range(10):
            records.append(self._make_record(ts_offset=4.0 + i * 0.2, label="flood"))

        df = extract_windows(records, window_seconds=2.0)
        assert len(df) >= 2
        assert "label" in df.columns
        # At least one normal window and one attack window
        assert (df["label"] == 0).any()
        assert (df["label"] == 1).any()


class TestShannonEntropy:
    """Unit tests for entropy calculation."""

    def test_empty(self):
        assert _shannon_entropy([]) == 0.0

    def test_single_value(self):
        assert _shannon_entropy(["a", "a", "a"]) == 0.0

    def test_uniform(self):
        """Uniform distribution should have max entropy."""
        values = ["a", "b", "c", "d"]
        entropy = _shannon_entropy(values)
        assert abs(entropy - 2.0) < 0.01  # log2(4) = 2.0

    def test_binary(self):
        """50/50 binary distribution should have entropy = 1.0."""
        values = ["a", "b"]
        entropy = _shannon_entropy(values)
        assert abs(entropy - 1.0) < 0.01


class TestTrafficLogIO:
    """Tests for log file I/O."""

    def test_load_valid_log(self):
        """Load a valid JSON-lines log file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(json.dumps({"timestamp": "2026-07-23T12:00:00Z", "service_id": "0x1001"}) + "\n")
            f.write(json.dumps({"timestamp": "2026-07-23T12:00:01Z", "service_id": "0x2001"}) + "\n")
            f.flush()

            records = load_traffic_log(f.name)
            assert len(records) == 2
            assert records[0]["service_id"] == "0x1001"

        os.unlink(f.name)

    def test_load_with_bad_lines(self):
        """Malformed lines should be skipped, not crash."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write(json.dumps({"service_id": "0x1001"}) + "\n")
            f.write("this is not json\n")
            f.write(json.dumps({"service_id": "0x2001"}) + "\n")
            f.flush()

            records = load_traffic_log(f.name)
            assert len(records) == 2

        os.unlink(f.name)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
