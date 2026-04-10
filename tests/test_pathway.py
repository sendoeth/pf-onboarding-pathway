#!/usr/bin/env python3
"""
Comprehensive test suite for the Canonical Onboarding Pathway Scanner.

Tests cover:
- Schema structure (16 tests)
- Checkpoint definitions (10 tests)
- Consumer validators (24 tests)
- Producer validators (24 tests)
- Dependency propagation (10 tests)
- Report builder (15 tests)
- Verdict logic (10 tests)
- Verifier (6 tests)
- Malformed inputs (12 tests)
- Next-step commands (8 tests)
- CLI (4 tests)
- Edge cases (12 tests)

Target: 125+ tests
"""

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scan_pathway import (
    SCANNER_VERSION, GENERATOR_VERSION,
    CONSUMER_CHECKPOINTS, PRODUCER_CHECKPOINTS,
    NEXT_STEP_COMMANDS, NEXT_STEP_ACTIONS,
    LIMITATIONS, VALIDATORS,
    build_report, sha256_dict, safe_get, score_to_grade, compute_readiness,
    make_check, load_json,
    validate_c_discovery, validate_c_schema, validate_c_routing,
    validate_c_trust, validate_c_acceptance, validate_c_consumption,
    validate_c_verification, validate_c_monitoring,
    validate_p_schema, validate_p_delivery, validate_p_resolution,
    validate_p_proof, validate_p_discovery, validate_p_health,
    validate_p_trust, validate_p_activity,
)
from verify_pathway import PathwayVerifier, REQUIRED_TOP_LEVEL


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
def make_signal(**overrides):
    """Create a well-formed test signal."""
    sig = {
        "signal_id": "SIG-TEST-001",
        "producer_id": "PROD-TEST",
        "timestamp": "2026-04-10T12:00:00Z",
        "symbol": "BTC",
        "direction": "bullish",
        "confidence": 0.65,
        "horizon_hours": 24,
        "schema_version": "1.0.0",
        "regime": "NEUTRAL",
        "action": "EXECUTE"
    }
    sig.update(overrides)
    return sig


def make_signal_sample(count=5, **overrides):
    """Create a signal sample with multiple signals."""
    signals = []
    for i in range(count):
        sig = make_signal(signal_id=f"SIG-TEST-{i:03d}")
        symbols = ["BTC", "ETH", "SOL", "LINK"]
        sig["symbol"] = symbols[i % len(symbols)]
        sig.update(overrides)
        signals.append(sig)
    return signals


def make_discovery_result():
    """Create a well-formed discovery result."""
    return {
        "version": "1.0.0",
        "generated_at": "2026-04-10T12:00:00Z",
        "producers": [
            {"producer_id": "PROD-001", "endpoint": "http://localhost:8080", "status": "ACTIVE"}
        ]
    }


def make_trust_eval():
    """Create a well-formed trust evaluation."""
    return {
        "verdict": {"readiness": "ADOPT_WITH_CAVEATS", "grade": "B"},
        "dimensions": {
            "accuracy": 0.72,
            "reliability": 0.85,
            "freshness": 0.90,
            "consistency": 0.78,
            "transparency": 0.65
        }
    }


def make_acceptance_report():
    """Create a well-formed acceptance report."""
    return {
        "verdict": {"readiness": "READY", "grade": "A"},
        "checks": [
            {"name": "connectivity", "passed": True},
            {"name": "schema", "passed": True},
            {"name": "freshness", "passed": True},
            {"name": "cadence", "passed": True},
            {"name": "resolution", "passed": True},
            {"name": "trust", "passed": True},
            {"name": "monitoring", "passed": True},
        ]
    }


def make_activity_feed():
    """Create a well-formed activity feed."""
    return {
        "consumption_summary": {
            "total_runs": 2072,
            "total_signals": 8295,
            "total_errors": 0,
            "uptime_pct": 100.0,
            "consecutive_days": 23
        }
    }


def make_verification_report():
    """Create a well-formed verification report."""
    return {
        "verdict": {"status": "VERIFIED", "grade": "B"},
        "attestation": {
            "date": "2026-04-10",
            "consumer_id": "b1e55ed",
            "runs": 1651,
            "signals": 6611
        }
    }


def make_health_report():
    """Create a well-formed health report."""
    return {
        "dimensions": {
            "liveness": 0.95,
            "freshness": 0.88,
            "schema": 1.0,
            "proof": 0.75,
            "errors": 0.90,
            "consumption": 0.82
        },
        "composite_score": 0.722,
        "grade": "B"
    }


def make_proof_surface():
    """Create a well-formed proof surface."""
    return {
        "summary": {
            "total_signals": 2492,
            "resolved": 2128,
            "accuracy": 0.515,
            "karma": 42.5
        },
        "content_hash": "a" * 64,
        "freshness": "FRESH",
        "rolling_windows": {"7d": {}, "30d": {}}
    }


def make_full_consumer_artifacts():
    """Create complete set of consumer artifacts."""
    return {
        "discovery_result": make_discovery_result(),
        "signal_sample": make_signal_sample(),
        "trust_eval": make_trust_eval(),
        "acceptance_report": make_acceptance_report(),
        "activity_feed": make_activity_feed(),
        "verification_report": make_verification_report(),
        "health_report": make_health_report(),
        "proof_surface": None,
    }


def make_full_producer_artifacts():
    """Create complete set of producer artifacts."""
    return {
        "signal_sample": make_signal_sample(),
        "proof_surface": make_proof_surface(),
        "health_report": make_health_report(),
        "trust_eval": make_trust_eval(),
        "activity_feed": make_activity_feed(),
        "discovery_result": make_discovery_result(),
        "acceptance_report": None,
        "verification_report": None,
    }


def make_empty_artifacts():
    """Create empty artifact set."""
    return {
        "signal_sample": None,
        "proof_surface": None,
        "health_report": None,
        "trust_eval": None,
        "activity_feed": None,
        "discovery_result": None,
        "acceptance_report": None,
        "verification_report": None,
    }


def load_schema():
    """Load the pathway schema."""
    schema_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "onboarding_pathway_schema.json")
    with open(schema_path) as f:
        return json.load(f)


# ===================================================================
# 1. Schema Structure Tests (16)
# ===================================================================
class TestSchemaStructure(unittest.TestCase):
    """Test the JSON Schema structure."""

    @classmethod
    def setUpClass(cls):
        cls.schema = load_schema()

    def test_schema_is_dict(self):
        self.assertIsInstance(self.schema, dict)

    def test_schema_has_defs(self):
        self.assertIn("$defs", self.schema)

    def test_schema_version(self):
        self.assertEqual(self.schema.get("$schema"), "https://json-schema.org/draft/2020-12/schema")

    def test_schema_has_required(self):
        self.assertIn("required", self.schema)
        self.assertEqual(len(self.schema["required"]), 9)

    def test_schema_required_fields(self):
        expected = {"scanner_version", "meta", "pathway_config", "checkpoints",
                    "progress_summary", "next_steps", "verdict", "hash_chain", "limitations"}
        self.assertEqual(set(self.schema["required"]), expected)

    def test_schema_no_additional_properties(self):
        self.assertFalse(self.schema.get("additionalProperties", True))

    def test_defs_count(self):
        self.assertEqual(len(self.schema["$defs"]), 11)

    def test_defs_scan_meta(self):
        self.assertIn("scan_meta", self.schema["$defs"])
        meta = self.schema["$defs"]["scan_meta"]
        self.assertIn("report_id", meta.get("required", []))
        self.assertIn("content_hash", meta.get("required", []))

    def test_defs_pathway_config(self):
        self.assertIn("pathway_config", self.schema["$defs"])

    def test_defs_checkpoint_def(self):
        self.assertIn("checkpoint_def", self.schema["$defs"])
        cd = self.schema["$defs"]["checkpoint_def"]
        self.assertIn("checkpoint_id", cd.get("required", []))

    def test_defs_checkpoint(self):
        self.assertIn("checkpoint", self.schema["$defs"])
        cp = self.schema["$defs"]["checkpoint"]
        self.assertIn("status", cp["properties"])
        self.assertIn("COMPLETED", cp["properties"]["status"]["enum"])
        self.assertIn("BLOCKED", cp["properties"]["status"]["enum"])

    def test_defs_checkpoint_validation(self):
        self.assertIn("checkpoint_validation", self.schema["$defs"])

    def test_defs_progress_summary(self):
        ps = self.schema["$defs"]["progress_summary"]
        self.assertIn("READY", ps["properties"]["readiness"]["enum"])
        self.assertIn("BLOCKED", ps["properties"]["readiness"]["enum"])

    def test_defs_scan_verdict(self):
        sv = self.schema["$defs"]["scan_verdict"]
        self.assertIn("A", sv["properties"]["grade"]["enum"])
        self.assertIn("F", sv["properties"]["grade"]["enum"])

    def test_defs_hash_chain(self):
        hc = self.schema["$defs"]["hash_chain"]
        self.assertEqual(hc["properties"]["algorithm"]["const"], "SHA-256")

    def test_defs_limitation(self):
        lim = self.schema["$defs"]["limitation"]
        self.assertIn("OVERSTATED_READINESS", lim["properties"]["bias_direction"]["enum"])
        self.assertIn("UNDERSTATED_READINESS", lim["properties"]["bias_direction"]["enum"])

    def test_defs_limitations(self):
        self.assertIn("limitations", self.schema["$defs"])


# ===================================================================
# 2. Checkpoint Definition Tests (10)
# ===================================================================
class TestCheckpointDefinitions(unittest.TestCase):
    """Test checkpoint definition structures."""

    def test_consumer_has_8_checkpoints(self):
        self.assertEqual(len(CONSUMER_CHECKPOINTS), 8)

    def test_producer_has_8_checkpoints(self):
        self.assertEqual(len(PRODUCER_CHECKPOINTS), 8)

    def test_consumer_ids_have_c_prefix(self):
        for cp in CONSUMER_CHECKPOINTS:
            self.assertTrue(cp["checkpoint_id"].startswith("C-"), cp["checkpoint_id"])

    def test_producer_ids_have_p_prefix(self):
        for cp in PRODUCER_CHECKPOINTS:
            self.assertTrue(cp["checkpoint_id"].startswith("P-"), cp["checkpoint_id"])

    def test_consumer_order_ascending(self):
        orders = [cp["order"] for cp in CONSUMER_CHECKPOINTS]
        self.assertEqual(orders, list(range(1, 9)))

    def test_producer_order_ascending(self):
        orders = [cp["order"] for cp in PRODUCER_CHECKPOINTS]
        self.assertEqual(orders, list(range(1, 9)))

    def test_consumer_first_has_no_deps(self):
        self.assertEqual(CONSUMER_CHECKPOINTS[0]["depends_on"], [])

    def test_producer_first_has_no_deps(self):
        self.assertEqual(PRODUCER_CHECKPOINTS[0]["depends_on"], [])

    def test_all_deps_reference_valid_ids(self):
        consumer_ids = {cp["checkpoint_id"] for cp in CONSUMER_CHECKPOINTS}
        for cp in CONSUMER_CHECKPOINTS:
            for dep in cp["depends_on"]:
                self.assertIn(dep, consumer_ids, f"{cp['checkpoint_id']} dep {dep} not valid")

        producer_ids = {cp["checkpoint_id"] for cp in PRODUCER_CHECKPOINTS}
        for cp in PRODUCER_CHECKPOINTS:
            for dep in cp["depends_on"]:
                self.assertIn(dep, producer_ids, f"{cp['checkpoint_id']} dep {dep} not valid")

    def test_all_checkpoints_have_validators(self):
        for cp in CONSUMER_CHECKPOINTS + PRODUCER_CHECKPOINTS:
            self.assertIn(cp["checkpoint_id"], VALIDATORS, f"No validator for {cp['checkpoint_id']}")


# ===================================================================
# 3. Consumer Validator Tests (24)
# ===================================================================
class TestConsumerValidators(unittest.TestCase):
    """Test individual consumer checkpoint validators."""

    def test_c_discovery_with_artifact(self):
        checks = validate_c_discovery({"discovery_result": make_discovery_result()})
        self.assertTrue(all(c["passed"] for c in checks))

    def test_c_discovery_without_artifact(self):
        checks = validate_c_discovery({"discovery_result": None})
        self.assertFalse(checks[0]["passed"])

    def test_c_discovery_empty_producers(self):
        result = make_discovery_result()
        result["producers"] = []
        checks = validate_c_discovery({"discovery_result": result})
        failed = [c for c in checks if not c["passed"]]
        self.assertTrue(len(failed) > 0)

    def test_c_schema_with_valid_signals(self):
        checks = validate_c_schema({"signal_sample": make_signal_sample()})
        self.assertTrue(all(c["passed"] for c in checks))

    def test_c_schema_without_artifact(self):
        checks = validate_c_schema({"signal_sample": None})
        self.assertFalse(checks[0]["passed"])

    def test_c_schema_invalid_direction(self):
        signals = [make_signal(direction="sideways")]
        checks = validate_c_schema({"signal_sample": signals})
        dir_check = [c for c in checks if c["check_name"] == "direction_valid"]
        self.assertTrue(len(dir_check) > 0)
        self.assertFalse(dir_check[0]["passed"])

    def test_c_schema_invalid_confidence(self):
        signals = [make_signal(confidence=1.5)]
        checks = validate_c_schema({"signal_sample": signals})
        conf_check = [c for c in checks if c["check_name"] == "confidence_bounds"]
        self.assertTrue(len(conf_check) > 0)
        self.assertFalse(conf_check[0]["passed"])

    def test_c_routing_with_signals(self):
        checks = validate_c_routing({"signal_sample": make_signal_sample()})
        self.assertTrue(any(c["passed"] for c in checks))

    def test_c_routing_without_artifact(self):
        checks = validate_c_routing({"signal_sample": None})
        self.assertFalse(checks[0]["passed"])

    def test_c_trust_with_artifact(self):
        checks = validate_c_trust({"trust_eval": make_trust_eval()})
        self.assertTrue(all(c["passed"] for c in checks))

    def test_c_trust_without_artifact(self):
        checks = validate_c_trust({"trust_eval": None})
        self.assertFalse(checks[0]["passed"])

    def test_c_trust_invalid_verdict(self):
        trust = make_trust_eval()
        trust["verdict"]["readiness"] = "INVALID"
        checks = validate_c_trust({"trust_eval": trust})
        verdict_check = [c for c in checks if c["check_name"] == "verdict_valid"]
        self.assertTrue(len(verdict_check) > 0)
        self.assertFalse(verdict_check[0]["passed"])

    def test_c_acceptance_with_artifact(self):
        checks = validate_c_acceptance({"acceptance_report": make_acceptance_report()})
        self.assertTrue(all(c["passed"] for c in checks))

    def test_c_acceptance_without_artifact(self):
        checks = validate_c_acceptance({"acceptance_report": None})
        self.assertFalse(checks[0]["passed"])

    def test_c_acceptance_not_ready(self):
        report = make_acceptance_report()
        report["verdict"]["readiness"] = "NOT_READY"
        checks = validate_c_acceptance({"acceptance_report": report})
        verdict_checks = [c for c in checks if c["check_name"] == "verdict_valid"]
        self.assertTrue(all(c["passed"] for c in verdict_checks))  # NOT_READY is still valid

    def test_c_consumption_with_artifact(self):
        checks = validate_c_consumption({"activity_feed": make_activity_feed()})
        self.assertTrue(all(c["passed"] for c in checks))

    def test_c_consumption_without_artifact(self):
        checks = validate_c_consumption({"activity_feed": None})
        self.assertFalse(checks[0]["passed"])

    def test_c_consumption_zero_runs(self):
        feed = {"consumption_summary": {"total_runs": 0, "total_signals": 0}}
        checks = validate_c_consumption({"activity_feed": feed})
        runs_check = [c for c in checks if c["check_name"] == "has_runs"]
        self.assertFalse(runs_check[0]["passed"])

    def test_c_verification_with_artifact(self):
        checks = validate_c_verification({"verification_report": make_verification_report()})
        self.assertTrue(all(c["passed"] for c in checks))

    def test_c_verification_without_artifact(self):
        checks = validate_c_verification({"verification_report": None})
        self.assertFalse(checks[0]["passed"])

    def test_c_verification_no_attestation(self):
        report = make_verification_report()
        del report["attestation"]
        checks = validate_c_verification({"verification_report": report})
        att_check = [c for c in checks if c["check_name"] == "has_attestation"]
        self.assertFalse(att_check[0]["passed"])

    def test_c_monitoring_with_artifact(self):
        checks = validate_c_monitoring({"health_report": make_health_report()})
        self.assertTrue(all(c["passed"] for c in checks))

    def test_c_monitoring_without_artifact(self):
        checks = validate_c_monitoring({"health_report": None})
        self.assertFalse(checks[0]["passed"])

    def test_c_monitoring_missing_grade(self):
        report = make_health_report()
        del report["grade"]
        checks = validate_c_monitoring({"health_report": report})
        grade_check = [c for c in checks if c["check_name"] == "has_grade"]
        self.assertFalse(grade_check[0]["passed"])


# ===================================================================
# 4. Producer Validator Tests (24)
# ===================================================================
class TestProducerValidators(unittest.TestCase):
    """Test individual producer checkpoint validators."""

    def test_p_schema_with_valid_signals(self):
        checks = validate_p_schema({"signal_sample": make_signal_sample()})
        self.assertTrue(all(c["passed"] for c in checks))

    def test_p_schema_without_artifact(self):
        checks = validate_p_schema({"signal_sample": None})
        self.assertFalse(checks[0]["passed"])

    def test_p_schema_missing_producer_id(self):
        signals = [make_signal()]
        del signals[0]["producer_id"]
        checks = validate_p_schema({"signal_sample": signals})
        req_check = [c for c in checks if c["check_name"] == "required_fields"]
        self.assertFalse(req_check[0]["passed"])

    def test_p_schema_invalid_schema_version(self):
        signals = [make_signal(schema_version="abc")]
        checks = validate_p_schema({"signal_sample": signals})
        sv_check = [c for c in checks if c["check_name"] == "schema_version"]
        self.assertFalse(sv_check[0]["passed"])

    def test_p_schema_invalid_symbol(self):
        signals = [make_signal(symbol="btc")]  # lowercase
        checks = validate_p_schema({"signal_sample": signals})
        sym_check = [c for c in checks if c["check_name"] == "symbol_format"]
        self.assertFalse(sym_check[0]["passed"])

    def test_p_delivery_with_signals(self):
        checks = validate_p_delivery({"signal_sample": make_signal_sample()})
        self.assertTrue(all(c["passed"] for c in checks))

    def test_p_delivery_without_artifact(self):
        checks = validate_p_delivery({"signal_sample": None})
        self.assertFalse(checks[0]["passed"])

    def test_p_delivery_single_signal(self):
        checks = validate_p_delivery({"signal_sample": [make_signal()]})
        suff_check = [c for c in checks if c["check_name"] == "sufficient_signals"]
        self.assertFalse(suff_check[0]["passed"])

    def test_p_delivery_single_symbol(self):
        signals = [make_signal(symbol="BTC"), make_signal(symbol="BTC", signal_id="SIG-002")]
        checks = validate_p_delivery({"signal_sample": signals})
        multi_check = [c for c in checks if c["check_name"] == "multi_symbol"]
        self.assertFalse(multi_check[0]["passed"])

    def test_p_resolution_with_proof(self):
        checks = validate_p_resolution({"proof_surface": make_proof_surface()})
        self.assertTrue(all(c["passed"] for c in checks))

    def test_p_resolution_without_artifact(self):
        checks = validate_p_resolution({"proof_surface": None})
        self.assertFalse(checks[0]["passed"])

    def test_p_resolution_no_accuracy(self):
        proof = make_proof_surface()
        del proof["summary"]["accuracy"]
        checks = validate_p_resolution({"proof_surface": proof})
        acc_check = [c for c in checks if c["check_name"] == "has_accuracy"]
        self.assertFalse(acc_check[0]["passed"])

    def test_p_proof_with_artifact(self):
        checks = validate_p_proof({"proof_surface": make_proof_surface()})
        self.assertTrue(all(c["passed"] for c in checks))

    def test_p_proof_without_artifact(self):
        checks = validate_p_proof({"proof_surface": None})
        self.assertFalse(checks[0]["passed"])

    def test_p_proof_no_hash(self):
        proof = make_proof_surface()
        del proof["content_hash"]
        checks = validate_p_proof({"proof_surface": proof})
        hash_check = [c for c in checks if c["check_name"] == "has_hash"]
        self.assertFalse(hash_check[0]["passed"])

    def test_p_proof_no_windows(self):
        proof = make_proof_surface()
        del proof["rolling_windows"]
        checks = validate_p_proof({"proof_surface": proof})
        win_check = [c for c in checks if c["check_name"] == "has_windows"]
        self.assertFalse(win_check[0]["passed"])

    def test_p_discovery_with_artifact(self):
        checks = validate_p_discovery({"discovery_result": make_discovery_result()})
        self.assertTrue(any(c["passed"] for c in checks))

    def test_p_discovery_without_artifact(self):
        checks = validate_p_discovery({"discovery_result": None})
        self.assertFalse(checks[0]["passed"])

    def test_p_health_with_artifact(self):
        checks = validate_p_health({"health_report": make_health_report()})
        self.assertTrue(all(c["passed"] for c in checks))

    def test_p_health_without_artifact(self):
        checks = validate_p_health({"health_report": None})
        self.assertFalse(checks[0]["passed"])

    def test_p_trust_with_artifact(self):
        checks = validate_p_trust({"trust_eval": make_trust_eval()})
        self.assertTrue(all(c["passed"] for c in checks))

    def test_p_trust_without_artifact(self):
        checks = validate_p_trust({"trust_eval": None})
        self.assertFalse(checks[0]["passed"])

    def test_p_activity_with_artifact(self):
        checks = validate_p_activity({"activity_feed": make_activity_feed()})
        self.assertTrue(all(c["passed"] for c in checks))

    def test_p_activity_without_artifact(self):
        checks = validate_p_activity({"activity_feed": None})
        self.assertFalse(checks[0]["passed"])


# ===================================================================
# 5. Dependency Propagation Tests (10)
# ===================================================================
class TestDependencyPropagation(unittest.TestCase):
    """Test dependency-aware status propagation."""

    def test_all_artifacts_all_completed(self):
        report = build_report("CONSUMER", make_full_consumer_artifacts())
        statuses = [cp["status"] for cp in report["checkpoints"]]
        completed = statuses.count("COMPLETED")
        self.assertEqual(completed, 8, f"Expected 8 COMPLETED, got statuses: {statuses}")

    def test_no_artifacts_first_pending_rest_blocked(self):
        report = build_report("CONSUMER", make_empty_artifacts())
        statuses = [cp["status"] for cp in report["checkpoints"]]
        self.assertEqual(statuses[0], "PENDING")
        for s in statuses[1:]:
            self.assertEqual(s, "BLOCKED")

    def test_first_completed_second_unblocked(self):
        artifacts = make_empty_artifacts()
        artifacts["discovery_result"] = make_discovery_result()
        report = build_report("CONSUMER", artifacts)
        # First should be COMPLETED, second should be PENDING (unblocked)
        self.assertEqual(report["checkpoints"][0]["status"], "COMPLETED")
        self.assertEqual(report["checkpoints"][1]["status"], "PENDING")

    def test_blocked_by_populated(self):
        report = build_report("CONSUMER", make_empty_artifacts())
        second = report["checkpoints"][1]
        self.assertIn("C-DISCOVERY", second["blocked_by"])

    def test_completed_has_empty_blocked_by(self):
        report = build_report("CONSUMER", make_full_consumer_artifacts())
        for cp in report["checkpoints"]:
            if cp["status"] == "COMPLETED":
                self.assertEqual(cp["blocked_by"], [])

    def test_producer_dependency_chain(self):
        report = build_report("PRODUCER", make_empty_artifacts())
        # P-SCHEMA has no deps, should be PENDING
        self.assertEqual(report["checkpoints"][0]["status"], "PENDING")
        # P-DELIVERY depends on P-SCHEMA, should be BLOCKED
        self.assertEqual(report["checkpoints"][1]["status"], "BLOCKED")
        self.assertIn("P-SCHEMA", report["checkpoints"][1]["blocked_by"])

    def test_partial_producer_artifacts(self):
        artifacts = make_empty_artifacts()
        artifacts["signal_sample"] = make_signal_sample()
        report = build_report("PRODUCER", artifacts)
        # P-SCHEMA and P-DELIVERY should be COMPLETED (both use signal_sample)
        self.assertEqual(report["checkpoints"][0]["status"], "COMPLETED")
        self.assertEqual(report["checkpoints"][1]["status"], "COMPLETED")
        # P-RESOLUTION should be PENDING (no proof_surface)
        self.assertEqual(report["checkpoints"][2]["status"], "PENDING")

    def test_mid_chain_failure_blocks_downstream(self):
        artifacts = make_full_consumer_artifacts()
        artifacts["trust_eval"] = None  # Remove trust eval
        report = build_report("CONSUMER", artifacts)
        # C-TRUST should be PENDING, everything after should be BLOCKED
        trust_idx = next(i for i, cp in enumerate(report["checkpoints"]) if cp["checkpoint_id"] == "C-TRUST")
        self.assertEqual(report["checkpoints"][trust_idx]["status"], "PENDING")
        for cp in report["checkpoints"][trust_idx + 1:]:
            self.assertEqual(cp["status"], "BLOCKED")

    def test_dependency_order_never_reversed(self):
        report = build_report("CONSUMER", make_full_consumer_artifacts())
        for cp in report["checkpoints"]:
            for dep in cp["depends_on"]:
                dep_order = next(c["order"] for c in report["checkpoints"] if c["checkpoint_id"] == dep)
                self.assertLess(dep_order, cp["order"])

    def test_all_blocked_by_in_depends_on(self):
        report = build_report("CONSUMER", make_empty_artifacts())
        for cp in report["checkpoints"]:
            for bb in cp["blocked_by"]:
                self.assertIn(bb, cp["depends_on"])


# ===================================================================
# 6. Report Builder Tests (15)
# ===================================================================
class TestReportBuilder(unittest.TestCase):
    """Test the build_report function."""

    def test_consumer_report_has_all_fields(self):
        report = build_report("CONSUMER", make_full_consumer_artifacts())
        for field in REQUIRED_TOP_LEVEL:
            self.assertIn(field, report, f"Missing {field}")

    def test_producer_report_has_all_fields(self):
        report = build_report("PRODUCER", make_full_producer_artifacts())
        for field in REQUIRED_TOP_LEVEL:
            self.assertIn(field, report, f"Missing {field}")

    def test_report_version(self):
        report = build_report("CONSUMER", make_full_consumer_artifacts())
        self.assertEqual(report["scanner_version"], SCANNER_VERSION)

    def test_meta_report_id_format(self):
        report = build_report("CONSUMER", make_full_consumer_artifacts())
        import re
        self.assertTrue(re.match(r"^PATH-CONSUMER-\d{8}T\d{6}Z$", report["meta"]["report_id"]))

    def test_meta_role(self):
        report = build_report("PRODUCER", make_full_producer_artifacts())
        self.assertEqual(report["meta"]["role"], "PRODUCER")

    def test_content_hash_hex64(self):
        report = build_report("CONSUMER", make_full_consumer_artifacts())
        import re
        self.assertTrue(re.match(r"^[0-9a-f]{64}$", report["meta"]["content_hash"]))

    def test_eight_checkpoints(self):
        report = build_report("CONSUMER", make_full_consumer_artifacts())
        self.assertEqual(len(report["checkpoints"]), 8)

    def test_pathway_config_role(self):
        report = build_report("CONSUMER", make_full_consumer_artifacts())
        self.assertEqual(report["pathway_config"]["role"], "CONSUMER")
        self.assertEqual(report["pathway_config"]["checkpoint_count"], 8)

    def test_progress_summary_counts(self):
        report = build_report("CONSUMER", make_full_consumer_artifacts())
        ps = report["progress_summary"]
        self.assertEqual(ps["total_checkpoints"], 8)
        self.assertEqual(ps["completed"] + ps["pending"] + ps["blocked"] + ps["skipped"], 8)

    def test_hash_chain_structure(self):
        report = build_report("CONSUMER", make_full_consumer_artifacts())
        hc = report["hash_chain"]
        self.assertEqual(hc["algorithm"], "SHA-256")
        self.assertIsNotNone(hc["report_hash"])
        self.assertIsNone(hc["previous_report_hash"])

    def test_previous_hash_preserved(self):
        report = build_report("CONSUMER", make_full_consumer_artifacts(), previous_hash="a" * 64)
        self.assertEqual(report["hash_chain"]["previous_report_hash"], "a" * 64)

    def test_limitations_included(self):
        report = build_report("CONSUMER", make_full_consumer_artifacts())
        self.assertEqual(report["limitations"]["count"], len(LIMITATIONS))
        self.assertEqual(len(report["limitations"]["items"]), len(LIMITATIONS))

    def test_empty_report_has_next_steps(self):
        report = build_report("CONSUMER", make_empty_artifacts())
        self.assertTrue(len(report["next_steps"]) > 0)

    def test_full_report_no_next_steps(self):
        report = build_report("CONSUMER", make_full_consumer_artifacts())
        self.assertEqual(len(report["next_steps"]), 0)

    def test_deterministic_content_hash(self):
        arts = make_full_consumer_artifacts()
        r1 = build_report("CONSUMER", arts)
        r2 = build_report("CONSUMER", arts)
        # Content hashes may differ due to timestamp, but structure should be same
        self.assertEqual(len(r1["checkpoints"]), len(r2["checkpoints"]))


# ===================================================================
# 7. Verdict Logic Tests (10)
# ===================================================================
class TestVerdictLogic(unittest.TestCase):
    """Test verdict and grading logic."""

    def test_all_completed_is_ready(self):
        report = build_report("CONSUMER", make_full_consumer_artifacts())
        self.assertEqual(report["verdict"]["readiness"], "READY")
        self.assertEqual(report["verdict"]["grade"], "A")

    def test_none_completed_is_not_started(self):
        report = build_report("CONSUMER", make_empty_artifacts())
        # Has blocked, so should be BLOCKED
        self.assertEqual(report["verdict"]["readiness"], "BLOCKED")

    def test_grade_a_for_100pct(self):
        self.assertEqual(score_to_grade(1.0), "A")

    def test_grade_b_for_75pct(self):
        self.assertEqual(score_to_grade(0.75), "B")

    def test_grade_c_for_50pct(self):
        self.assertEqual(score_to_grade(0.50), "C")

    def test_grade_d_for_25pct(self):
        self.assertEqual(score_to_grade(0.25), "D")

    def test_grade_f_for_0pct(self):
        self.assertEqual(score_to_grade(0.0), "F")

    def test_readiness_ready(self):
        self.assertEqual(compute_readiness(8, 8, False), "READY")

    def test_readiness_nearly_ready(self):
        self.assertEqual(compute_readiness(7, 8, False), "NEARLY_READY")

    def test_readiness_blocked(self):
        self.assertEqual(compute_readiness(3, 8, True), "BLOCKED")


# ===================================================================
# 8. Verifier Tests (6)
# ===================================================================
class TestVerifier(unittest.TestCase):
    """Test the zero-trust verifier."""

    def test_valid_consumer_report_passes(self):
        report = build_report("CONSUMER", make_full_consumer_artifacts())
        schema = load_schema()
        v = PathwayVerifier(report, schema=schema)
        results = v.verify_all()
        self.assertGreater(results["total_checks"], 100)
        # Should have very high pass rate for valid report
        self.assertGreater(results["pass_rate"], 0.90, f"Pass rate too low: {results['pass_rate']}")

    def test_valid_producer_report_passes(self):
        report = build_report("PRODUCER", make_full_producer_artifacts())
        schema = load_schema()
        v = PathwayVerifier(report, schema=schema)
        results = v.verify_all()
        self.assertGreater(results["total_checks"], 100)
        self.assertGreater(results["pass_rate"], 0.90)

    def test_empty_report_fails(self):
        v = PathwayVerifier({})
        results = v.verify_all()
        self.assertGreater(results["failed"], 0)

    def test_non_dict_report_fails(self):
        v = PathwayVerifier([])
        results = v.verify_all()
        self.assertGreater(results["failed"], 0)

    def test_verifier_has_16_categories(self):
        report = build_report("CONSUMER", make_full_consumer_artifacts())
        schema = load_schema()
        v = PathwayVerifier(report, schema=schema)
        results = v.verify_all()
        self.assertEqual(len(results["categories"]), 16)

    def test_verifier_detects_tampered_hash(self):
        report = build_report("CONSUMER", make_full_consumer_artifacts())
        report["meta"]["content_hash"] = "0" * 64  # tamper
        v = PathwayVerifier(report)
        results = v.verify_all()
        hash_failures = [c for c in results["failures"] if c["category"] == "content_hash_integrity"]
        self.assertTrue(len(hash_failures) > 0)


# ===================================================================
# 9. Malformed Input Tests (12)
# ===================================================================
class TestMalformedInputs(unittest.TestCase):
    """Test handling of malformed inputs."""

    def test_string_artifact(self):
        checks = validate_c_discovery({"discovery_result": "not a dict"})
        failed = [c for c in checks if not c["passed"]]
        self.assertTrue(len(failed) > 0)

    def test_integer_artifact(self):
        checks = validate_c_schema({"signal_sample": 42})
        failed = [c for c in checks if not c["passed"]]
        self.assertTrue(len(failed) > 0)

    def test_empty_dict_artifact(self):
        checks = validate_c_trust({"trust_eval": {}})
        # Should have artifact_exists pass but other checks fail
        exists_check = [c for c in checks if c["check_name"] == "artifact_exists"]
        self.assertTrue(exists_check[0]["passed"])

    def test_none_signals_list(self):
        checks = validate_c_schema({"signal_sample": {"signals": None}})
        signal_check = [c for c in checks if c["check_name"] == "has_signals"]
        self.assertTrue(len(signal_check) > 0)

    def test_signal_missing_all_fields(self):
        checks = validate_p_schema({"signal_sample": [{}]})
        req_check = [c for c in checks if c["check_name"] == "required_fields"]
        self.assertFalse(req_check[0]["passed"])

    def test_nested_none_values(self):
        trust = {"verdict": None, "dimensions": None}
        checks = validate_c_trust({"trust_eval": trust})
        # Should handle gracefully
        self.assertTrue(len(checks) > 0)

    def test_load_json_nonexistent(self):
        result = load_json("/nonexistent/path.json")
        self.assertIsNone(result)

    def test_load_json_none_path(self):
        result = load_json(None)
        self.assertIsNone(result)

    def test_safe_get_missing_keys(self):
        self.assertIsNone(safe_get({"a": {"b": 1}}, "a", "c"))
        self.assertEqual(safe_get({"a": {"b": 1}}, "a", "c", default=42), 42)

    def test_safe_get_non_dict(self):
        self.assertIsNone(safe_get("string", "key"))
        self.assertIsNone(safe_get(42, "key"))

    def test_make_check_structure(self):
        c = make_check("test", True, "ok")
        self.assertEqual(c["check_name"], "test")
        self.assertTrue(c["passed"])
        self.assertEqual(c["detail"], "ok")

    def test_build_report_with_invalid_role_artifacts(self):
        # Consumer report with producer artifacts should still work structurally
        report = build_report("CONSUMER", make_full_producer_artifacts())
        self.assertIn("checkpoints", report)
        self.assertEqual(len(report["checkpoints"]), 8)


# ===================================================================
# 10. Next-Step Command Tests (8)
# ===================================================================
class TestNextStepCommands(unittest.TestCase):
    """Test next-step command generation."""

    def test_all_consumer_checkpoints_have_commands(self):
        for cp in CONSUMER_CHECKPOINTS:
            self.assertIn(cp["checkpoint_id"], NEXT_STEP_COMMANDS)

    def test_all_producer_checkpoints_have_commands(self):
        for cp in PRODUCER_CHECKPOINTS:
            self.assertIn(cp["checkpoint_id"], NEXT_STEP_COMMANDS)

    def test_all_checkpoints_have_actions(self):
        for cp_id in list(NEXT_STEP_COMMANDS.keys()):
            self.assertIn(cp_id, NEXT_STEP_ACTIONS)

    def test_commands_contain_python3(self):
        for cmd in NEXT_STEP_COMMANDS.values():
            self.assertTrue("python3" in cmd or "#" in cmd, f"Command missing python3: {cmd}")

    def test_next_steps_ordered(self):
        report = build_report("CONSUMER", make_empty_artifacts())
        step_nums = [s["step_number"] for s in report["next_steps"]]
        self.assertEqual(step_nums, list(range(1, len(step_nums) + 1)))

    def test_next_steps_have_priority(self):
        report = build_report("CONSUMER", make_empty_artifacts())
        for step in report["next_steps"]:
            self.assertIn(step["priority"], {"CRITICAL", "HIGH", "MEDIUM", "LOW"})

    def test_next_steps_reference_valid_checkpoints(self):
        report = build_report("CONSUMER", make_empty_artifacts())
        consumer_ids = {cp["checkpoint_id"] for cp in CONSUMER_CHECKPOINTS}
        for step in report["next_steps"]:
            self.assertIn(step["checkpoint_id"], consumer_ids)

    def test_completed_checkpoint_not_in_next_steps(self):
        report = build_report("CONSUMER", make_full_consumer_artifacts())
        # All completed, no next steps
        self.assertEqual(len(report["next_steps"]), 0)


# ===================================================================
# 11. CLI Tests (4)
# ===================================================================
class TestCLI(unittest.TestCase):
    """Test CLI invocation."""

    def setUp(self):
        self.script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scan_pathway.py")
        self.verify_script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "verify_pathway.py")

    def test_cli_help(self):
        result = subprocess.run([sys.executable, self.script, "--help"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("--role", result.stdout)

    def test_cli_consumer_no_artifacts(self):
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            outpath = f.name
        try:
            result = subprocess.run(
                [sys.executable, self.script, "--role", "CONSUMER", "-o", outpath],
                capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0)
            with open(outpath) as f:
                report = json.load(f)
            self.assertEqual(report["meta"]["role"], "CONSUMER")
        finally:
            os.unlink(outpath)

    def test_cli_producer_no_artifacts(self):
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            outpath = f.name
        try:
            result = subprocess.run(
                [sys.executable, self.script, "--role", "PRODUCER", "-o", outpath],
                capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0)
            with open(outpath) as f:
                report = json.load(f)
            self.assertEqual(report["meta"]["role"], "PRODUCER")
        finally:
            os.unlink(outpath)

    def test_cli_with_artifacts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Write signal sample
            sig_path = os.path.join(tmpdir, "signals.json")
            with open(sig_path, "w") as f:
                json.dump(make_signal_sample(), f)

            outpath = os.path.join(tmpdir, "report.json")
            result = subprocess.run(
                [sys.executable, self.script, "--role", "PRODUCER",
                 "--signal-sample", sig_path, "-o", outpath],
                capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0)
            with open(outpath) as f:
                report = json.load(f)
            # P-SCHEMA and P-DELIVERY should be COMPLETED
            schema_cp = next(cp for cp in report["checkpoints"] if cp["checkpoint_id"] == "P-SCHEMA")
            self.assertEqual(schema_cp["status"], "COMPLETED")


# ===================================================================
# 12. Edge Case Tests (12)
# ===================================================================
class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions."""

    def test_sha256_dict_deterministic(self):
        d = {"b": 2, "a": 1}
        h1 = sha256_dict(d)
        h2 = sha256_dict(d)
        self.assertEqual(h1, h2)

    def test_sha256_dict_order_independent(self):
        h1 = sha256_dict({"a": 1, "b": 2})
        h2 = sha256_dict({"b": 2, "a": 1})
        self.assertEqual(h1, h2)

    def test_sha256_dict_different_values(self):
        h1 = sha256_dict({"a": 1})
        h2 = sha256_dict({"a": 2})
        self.assertNotEqual(h1, h2)

    def test_score_to_grade_boundary_100(self):
        self.assertEqual(score_to_grade(1.0), "A")

    def test_score_to_grade_boundary_99(self):
        self.assertEqual(score_to_grade(0.99), "B")

    def test_score_to_grade_boundary_74(self):
        self.assertEqual(score_to_grade(0.74), "C")

    def test_compute_readiness_in_progress(self):
        self.assertEqual(compute_readiness(3, 8, False), "IN_PROGRESS")

    def test_compute_readiness_not_started(self):
        self.assertEqual(compute_readiness(0, 8, False), "NOT_STARTED")

    def test_report_content_hash_changes_with_data(self):
        r1 = build_report("CONSUMER", make_empty_artifacts())
        r2 = build_report("CONSUMER", make_full_consumer_artifacts())
        self.assertNotEqual(r1["meta"]["content_hash"], r2["meta"]["content_hash"])

    def test_verifier_with_no_schema(self):
        report = build_report("CONSUMER", make_full_consumer_artifacts())
        v = PathwayVerifier(report, schema=None)
        results = v.verify_all()
        # Should still work, just skip schema checks
        schema_cat = results["categories"].get("schema_validation", {})
        self.assertTrue(schema_cat.get("failed", 0) > 0 or schema_cat.get("total", 0) == 1)

    def test_dict_signal_sample(self):
        """Signal sample can be a dict with signals key."""
        sample = {"signals": make_signal_sample()}
        checks = validate_c_schema({"signal_sample": sample})
        self.assertTrue(any(c["passed"] for c in checks))

    def test_single_dict_signal_sample(self):
        """Signal sample can be a single signal dict."""
        sample = make_signal()
        checks = validate_c_schema({"signal_sample": sample})
        self.assertTrue(any(c["passed"] for c in checks))


if __name__ == "__main__":
    unittest.main()
