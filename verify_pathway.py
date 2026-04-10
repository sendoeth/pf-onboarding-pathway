#!/usr/bin/env python3
"""
Zero-Trust Onboarding Pathway Verifier

Validates pathway scanner reports across 16 categories with 800+ checks.
Produces structured verification output with per-category pass rates.

Zero external dependencies — stdlib only.

Usage:
    python3 verify_pathway.py examples/producer_pathway_report.json examples/consumer_pathway_report.json
"""

import hashlib
import json
import os
import re
import sys
from datetime import datetime

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
EXPECTED_VERSION = "1.0.0"
REQUIRED_TOP_LEVEL = [
    "scanner_version", "meta", "pathway_config", "checkpoints",
    "progress_summary", "next_steps", "verdict", "hash_chain", "limitations"
]
VALID_STATUSES = {"COMPLETED", "PENDING", "BLOCKED", "SKIPPED"}
VALID_READINESS = {"READY", "NEARLY_READY", "IN_PROGRESS", "NOT_STARTED", "BLOCKED"}
VALID_GRADES = {"A", "B", "C", "D", "F"}
VALID_ROLES = {"PRODUCER", "CONSUMER"}
VALID_PRIORITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
VALID_BIAS_DIRS = {"OVERSTATED_READINESS", "UNDERSTATED_READINESS", "INDETERMINATE"}
VALID_BIAS_MAGS = {"LOW", "MEDIUM", "HIGH"}

CONSUMER_IDS = ["C-DISCOVERY", "C-SCHEMA", "C-ROUTING", "C-TRUST",
                "C-ACCEPTANCE", "C-CONSUMPTION", "C-VERIFICATION", "C-MONITORING"]
PRODUCER_IDS = ["P-SCHEMA", "P-DELIVERY", "P-RESOLUTION", "P-PROOF",
                "P-DISCOVERY", "P-HEALTH", "P-TRUST", "P-ACTIVITY"]

META_REQUIRED = ["report_id", "generated_at", "generator_version", "content_hash", "role", "scan_date"]
CHECKPOINT_REQUIRED = ["checkpoint_id", "checkpoint_name", "order", "status", "validation", "depends_on", "blocked_by"]
VALIDATION_REQUIRED = ["checks_run", "checks_passed", "checks_failed", "pass_rate", "details"]
DETAIL_REQUIRED = ["check_name", "passed", "detail"]
PROGRESS_REQUIRED = ["total_checkpoints", "completed", "pending", "blocked", "skipped", "completion_rate", "readiness"]
NEXT_STEP_REQUIRED = ["step_number", "checkpoint_id", "action", "command", "priority"]
VERDICT_REQUIRED = ["readiness", "grade", "completion_rate", "rationale", "recommendation"]
HASH_CHAIN_REQUIRED = ["algorithm", "report_hash", "previous_report_hash"]
LIMITATION_REQUIRED = ["id", "description", "bias_direction", "bias_magnitude"]
CHECKPOINT_DEF_REQUIRED = ["checkpoint_id", "checkpoint_name", "order", "depends_on", "protocol", "description"]
PATHWAY_CONFIG_REQUIRED = ["role", "checkpoint_count", "checkpoint_definitions"]


def sha256_dict(d):
    """Deterministic SHA-256 of a dict."""
    raw = json.dumps(d, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class PathwayVerifier:
    """Zero-trust verifier for onboarding pathway reports."""

    def __init__(self, report, schema=None):
        self.report = report
        self.schema = schema
        self.checks = []
        self.categories = {}

    def _record(self, category, name, passed, detail=""):
        """Record a single check result."""
        entry = {
            "category": category,
            "check_name": name,
            "passed": bool(passed),
            "detail": str(detail)
        }
        self.checks.append(entry)
        if category not in self.categories:
            self.categories[category] = {"passed": 0, "failed": 0, "total": 0}
        self.categories[category]["total"] += 1
        if passed:
            self.categories[category]["passed"] += 1
        else:
            self.categories[category]["failed"] += 1

    def verify_all(self):
        """Run all verification categories."""
        self.verify_structure()
        if not isinstance(self.report, dict):
            return self.get_results()
        self.verify_version()
        self.verify_meta()
        self.verify_pathway_config()
        self.verify_checkpoints_structure()
        self.verify_checkpoint_validations()
        self.verify_dependencies()
        self.verify_progress_summary()
        self.verify_next_steps()
        self.verify_verdict()
        self.verify_hash_chain()
        self.verify_content_hash_integrity()
        self.verify_limitations()
        self.verify_cross_consistency()
        self.verify_role_specific()
        self.verify_schema_validation()
        return self.get_results()

    # ------------------------------------------------------------------
    # 1. Structure
    # ------------------------------------------------------------------
    def verify_structure(self):
        cat = "structure"
        self._record(cat, "report_is_dict", isinstance(self.report, dict),
                     "Report is a dict" if isinstance(self.report, dict) else f"Report is {type(self.report).__name__}")

        if not isinstance(self.report, dict):
            return

        for field in REQUIRED_TOP_LEVEL:
            self._record(cat, f"has_{field}", field in self.report,
                         f"Has {field}" if field in self.report else f"Missing {field}")

        # No extra top-level keys
        extra = set(self.report.keys()) - set(REQUIRED_TOP_LEVEL)
        self._record(cat, "no_extra_keys", len(extra) == 0,
                     "No extra keys" if not extra else f"Extra keys: {extra}")

    # ------------------------------------------------------------------
    # 2. Version
    # ------------------------------------------------------------------
    def verify_version(self):
        cat = "version"
        sv = self.report.get("scanner_version")
        self._record(cat, "scanner_version_present", sv is not None, f"scanner_version={sv}")
        self._record(cat, "scanner_version_correct", sv == EXPECTED_VERSION,
                     f"Expected {EXPECTED_VERSION}, got {sv}")
        self._record(cat, "scanner_version_semver", bool(re.match(r"^\d+\.\d+\.\d+$", str(sv or ""))),
                     f"Valid semver: {sv}")

    # ------------------------------------------------------------------
    # 3. Meta
    # ------------------------------------------------------------------
    def verify_meta(self):
        cat = "meta"
        meta = self.report.get("meta", {})
        self._record(cat, "meta_is_dict", isinstance(meta, dict), "meta is dict")

        if not isinstance(meta, dict):
            return

        for field in META_REQUIRED:
            self._record(cat, f"has_{field}", field in meta,
                         f"Has {field}" if field in meta else f"Missing {field}")

        # Report ID format
        rid = meta.get("report_id", "")
        rid_ok = bool(re.match(r"^PATH-(PRODUCER|CONSUMER)-\d{8}T\d{6}Z$", str(rid)))
        self._record(cat, "report_id_format", rid_ok, f"Report ID format: {rid}")

        # Content hash format
        ch = meta.get("content_hash", "")
        ch_ok = bool(re.match(r"^[0-9a-f]{64}$", str(ch)))
        self._record(cat, "content_hash_format", ch_ok, f"Content hash hex-64: {ch[:16]}...")

        # Generated at parseable
        ga = meta.get("generated_at", "")
        try:
            datetime.fromisoformat(str(ga).replace("Z", "+00:00"))
            ga_ok = True
        except (ValueError, TypeError):
            ga_ok = False
        self._record(cat, "generated_at_parseable", ga_ok, f"Parseable: {ga}")

        # Role valid
        role = meta.get("role", "")
        self._record(cat, "role_valid", role in VALID_ROLES, f"Role: {role}")

        # Scan date format
        sd = meta.get("scan_date", "")
        sd_ok = bool(re.match(r"^\d{4}-\d{2}-\d{2}$", str(sd)))
        self._record(cat, "scan_date_format", sd_ok, f"Scan date: {sd}")

        # Generator version semver
        gv = meta.get("generator_version", "")
        gv_ok = bool(re.match(r"^\d+\.\d+\.\d+$", str(gv)))
        self._record(cat, "generator_version_semver", gv_ok, f"Generator version: {gv}")

        # Report ID contains correct role
        if rid_ok:
            role_in_id = "PRODUCER" if "PRODUCER" in rid else "CONSUMER" if "CONSUMER" in rid else ""
            self._record(cat, "report_id_role_match", role_in_id == role,
                         f"Report ID role={role_in_id} matches meta role={role}")

    # ------------------------------------------------------------------
    # 4. Pathway Config
    # ------------------------------------------------------------------
    def verify_pathway_config(self):
        cat = "pathway_config"
        pc = self.report.get("pathway_config", {})
        self._record(cat, "is_dict", isinstance(pc, dict), "pathway_config is dict")

        if not isinstance(pc, dict):
            return

        for field in PATHWAY_CONFIG_REQUIRED:
            self._record(cat, f"has_{field}", field in pc,
                         f"Has {field}" if field in pc else f"Missing {field}")

        # Role valid
        role = pc.get("role", "")
        self._record(cat, "role_valid", role in VALID_ROLES, f"Role: {role}")

        # Checkpoint count
        cc = pc.get("checkpoint_count", 0)
        self._record(cat, "checkpoint_count_is_8", cc == 8, f"Checkpoint count: {cc}")

        # Definitions
        defs = pc.get("checkpoint_definitions", [])
        self._record(cat, "defs_is_list", isinstance(defs, list), "Definitions is list")
        self._record(cat, "defs_count_is_8", len(defs) == 8 if isinstance(defs, list) else False,
                     f"Definition count: {len(defs) if isinstance(defs, list) else 'N/A'}")

        if isinstance(defs, list):
            for i, d in enumerate(defs):
                if isinstance(d, dict):
                    for field in CHECKPOINT_DEF_REQUIRED:
                        self._record(cat, f"def_{i}_has_{field}", field in d,
                                     f"Def {i} has {field}" if field in d else f"Def {i} missing {field}")

                    # Order monotonic
                    order = d.get("order", -1)
                    self._record(cat, f"def_{i}_order_{order}", order == i + 1,
                                 f"Def {i} order={order}, expected {i+1}")

                    # Depends_on is list
                    deps = d.get("depends_on", None)
                    self._record(cat, f"def_{i}_deps_is_list", isinstance(deps, list),
                                 f"Def {i} depends_on is list")

                    # Description length
                    desc = d.get("description", "")
                    self._record(cat, f"def_{i}_desc_len", len(str(desc)) >= 10,
                                 f"Def {i} description length: {len(str(desc))}")

                    # Protocol non-empty
                    proto = d.get("protocol", "")
                    self._record(cat, f"def_{i}_has_protocol", len(str(proto)) > 0,
                                 f"Def {i} protocol: {proto}")

    # ------------------------------------------------------------------
    # 5. Checkpoints Structure
    # ------------------------------------------------------------------
    def verify_checkpoints_structure(self):
        cat = "checkpoints_structure"
        cps = self.report.get("checkpoints", [])
        self._record(cat, "is_list", isinstance(cps, list), "checkpoints is list")
        self._record(cat, "count_is_8", len(cps) == 8 if isinstance(cps, list) else False,
                     f"Checkpoint count: {len(cps) if isinstance(cps, list) else 'N/A'}")

        if not isinstance(cps, list):
            return

        ids_seen = set()
        for i, cp in enumerate(cps):
            self._record(cat, f"cp_{i}_is_dict", isinstance(cp, dict), f"Checkpoint {i} is dict")
            if not isinstance(cp, dict):
                continue

            for field in CHECKPOINT_REQUIRED:
                self._record(cat, f"cp_{i}_has_{field}", field in cp,
                             f"CP {i} has {field}" if field in cp else f"CP {i} missing {field}")

            # Status valid
            status = cp.get("status", "")
            self._record(cat, f"cp_{i}_status_valid", status in VALID_STATUSES,
                         f"CP {i} status: {status}")

            # Order matches position
            order = cp.get("order", -1)
            self._record(cat, f"cp_{i}_order_correct", order == i + 1,
                         f"CP {i} order={order}, expected {i+1}")

            # ID unique
            cp_id = cp.get("checkpoint_id", "")
            self._record(cat, f"cp_{i}_id_unique", cp_id not in ids_seen,
                         f"CP {i} id={cp_id} unique" if cp_id not in ids_seen else f"Duplicate id: {cp_id}")
            ids_seen.add(cp_id)

            # Depends_on is list
            deps = cp.get("depends_on", None)
            self._record(cat, f"cp_{i}_deps_is_list", isinstance(deps, list),
                         f"CP {i} depends_on is list")

            # Blocked_by is list
            bb = cp.get("blocked_by", None)
            self._record(cat, f"cp_{i}_blocked_by_is_list", isinstance(bb, list),
                         f"CP {i} blocked_by is list")

    # ------------------------------------------------------------------
    # 6. Checkpoint Validations
    # ------------------------------------------------------------------
    def verify_checkpoint_validations(self):
        cat = "checkpoint_validations"
        cps = self.report.get("checkpoints", [])
        if not isinstance(cps, list):
            return

        for i, cp in enumerate(cps):
            if not isinstance(cp, dict):
                continue

            val = cp.get("validation", {})
            self._record(cat, f"cp_{i}_val_is_dict", isinstance(val, dict),
                         f"CP {i} validation is dict")
            if not isinstance(val, dict):
                continue

            for field in VALIDATION_REQUIRED:
                self._record(cat, f"cp_{i}_val_has_{field}", field in val,
                             f"CP {i} val has {field}" if field in val else f"CP {i} val missing {field}")

            # Arithmetic consistency
            run = val.get("checks_run", 0)
            passed = val.get("checks_passed", 0)
            failed = val.get("checks_failed", 0)
            self._record(cat, f"cp_{i}_arithmetic", run == passed + failed,
                         f"CP {i}: {run} = {passed} + {failed}" if run == passed + failed
                         else f"CP {i}: {run} != {passed} + {failed}")

            # Pass rate consistency
            pr = val.get("pass_rate", -1)
            expected_pr = round(passed / run, 4) if run > 0 else 0.0
            self._record(cat, f"cp_{i}_pass_rate", abs(pr - expected_pr) < 0.001,
                         f"CP {i} pass_rate={pr}, expected={expected_pr}")

            # Pass rate bounds
            self._record(cat, f"cp_{i}_pass_rate_bounds", 0 <= pr <= 1,
                         f"CP {i} pass_rate={pr} in [0,1]")

            # Details is list
            details = val.get("details", None)
            self._record(cat, f"cp_{i}_details_is_list", isinstance(details, list),
                         f"CP {i} details is list")

            if isinstance(details, list):
                # Details count matches checks_run
                self._record(cat, f"cp_{i}_details_count", len(details) == run,
                             f"CP {i} details count={len(details)}, checks_run={run}")

                # Each detail has required fields
                for j, d in enumerate(details):
                    if isinstance(d, dict):
                        for field in DETAIL_REQUIRED:
                            self._record(cat, f"cp_{i}_detail_{j}_has_{field}", field in d,
                                         f"CP {i} detail {j} has {field}" if field in d
                                         else f"CP {i} detail {j} missing {field}")

                        # Passed is bool
                        p = d.get("passed", None)
                        self._record(cat, f"cp_{i}_detail_{j}_passed_bool", isinstance(p, bool),
                                     f"CP {i} detail {j} passed is bool")

                        # Detail is string
                        dt = d.get("detail", None)
                        self._record(cat, f"cp_{i}_detail_{j}_detail_str", isinstance(dt, str),
                                     f"CP {i} detail {j} detail is string")

                # Count of passed details matches checks_passed
                detail_passed = sum(1 for d in details if isinstance(d, dict) and d.get("passed") is True)
                self._record(cat, f"cp_{i}_detail_passed_count", detail_passed == passed,
                             f"CP {i} detail passed={detail_passed}, checks_passed={passed}")

    # ------------------------------------------------------------------
    # 7. Dependencies
    # ------------------------------------------------------------------
    def verify_dependencies(self):
        cat = "dependencies"
        cps = self.report.get("checkpoints", [])
        if not isinstance(cps, list):
            return

        status_map = {}
        for cp in cps:
            if isinstance(cp, dict):
                status_map[cp.get("checkpoint_id", "")] = cp.get("status", "")

        role = self.report.get("meta", {}).get("role", "")
        valid_ids = set(CONSUMER_IDS if role == "CONSUMER" else PRODUCER_IDS)

        for i, cp in enumerate(cps):
            if not isinstance(cp, dict):
                continue

            cp_id = cp.get("checkpoint_id", "")
            deps = cp.get("depends_on", [])
            blocked_by = cp.get("blocked_by", [])
            status = cp.get("status", "")

            # All deps reference valid checkpoint IDs
            if isinstance(deps, list):
                for dep in deps:
                    self._record(cat, f"cp_{i}_dep_{dep}_valid", dep in valid_ids,
                                 f"CP {i} dep {dep} is valid ID" if dep in valid_ids
                                 else f"CP {i} dep {dep} is invalid")

                # No self-dependency
                self._record(cat, f"cp_{i}_no_self_dep", cp_id not in deps,
                             f"CP {i} no self-dependency" if cp_id not in deps
                             else f"CP {i} depends on itself")

                # No forward dependencies (deps should have lower order)
                cp_order = cp.get("order", 99)
                for dep in deps:
                    dep_order = next((c.get("order", 0) for c in cps if isinstance(c, dict) and c.get("checkpoint_id") == dep), 0)
                    self._record(cat, f"cp_{i}_dep_{dep}_lower_order", dep_order < cp_order,
                                 f"Dep {dep} (order {dep_order}) < CP {cp_id} (order {cp_order})")

            # Blocked_by consistency
            if isinstance(blocked_by, list):
                for bb in blocked_by:
                    # Blocked_by should be in deps
                    self._record(cat, f"cp_{i}_bb_{bb}_in_deps", bb in (deps or []),
                                 f"CP {i} blocked_by {bb} is in depends_on")

                    # Blocked_by items should not be COMPLETED
                    bb_status = status_map.get(bb, "")
                    self._record(cat, f"cp_{i}_bb_{bb}_not_completed", bb_status != "COMPLETED",
                                 f"Blocker {bb} status={bb_status}, not COMPLETED")

            # If BLOCKED, must have blocked_by entries
            if status == "BLOCKED":
                self._record(cat, f"cp_{i}_blocked_has_blockers", len(blocked_by) > 0,
                             f"BLOCKED CP {i} has {len(blocked_by)} blocker(s)")

            # If COMPLETED, blocked_by should be empty
            if status == "COMPLETED":
                self._record(cat, f"cp_{i}_completed_no_blockers", len(blocked_by) == 0,
                             f"COMPLETED CP {i} has no blockers" if not blocked_by
                             else f"COMPLETED CP {i} has blockers: {blocked_by}")

    # ------------------------------------------------------------------
    # 8. Progress Summary
    # ------------------------------------------------------------------
    def verify_progress_summary(self):
        cat = "progress_summary"
        ps = self.report.get("progress_summary", {})
        self._record(cat, "is_dict", isinstance(ps, dict), "progress_summary is dict")

        if not isinstance(ps, dict):
            return

        for field in PROGRESS_REQUIRED:
            self._record(cat, f"has_{field}", field in ps,
                         f"Has {field}" if field in ps else f"Missing {field}")

        # Total = 8
        total = ps.get("total_checkpoints", 0)
        self._record(cat, "total_is_8", total == 8, f"Total: {total}")

        # Counts sum to total
        c = ps.get("completed", 0)
        p = ps.get("pending", 0)
        b = ps.get("blocked", 0)
        s = ps.get("skipped", 0)
        self._record(cat, "counts_sum", c + p + b + s == total,
                     f"{c}+{p}+{b}+{s} = {c+p+b+s}, expected {total}")

        # Completion rate
        cr = ps.get("completion_rate", -1)
        expected_cr = round(c / total, 4) if total > 0 else 0.0
        self._record(cat, "completion_rate_correct", abs(cr - expected_cr) < 0.001,
                     f"completion_rate={cr}, expected={expected_cr}")

        # Completion rate bounds
        self._record(cat, "completion_rate_bounds", 0 <= cr <= 1, f"completion_rate={cr} in [0,1]")

        # Readiness valid
        readiness = ps.get("readiness", "")
        self._record(cat, "readiness_valid", readiness in VALID_READINESS, f"Readiness: {readiness}")

        # Readiness consistency with counts
        cps = self.report.get("checkpoints", [])
        actual_completed = sum(1 for cp in cps if isinstance(cp, dict) and cp.get("status") == "COMPLETED")
        actual_pending = sum(1 for cp in cps if isinstance(cp, dict) and cp.get("status") == "PENDING")
        actual_blocked = sum(1 for cp in cps if isinstance(cp, dict) and cp.get("status") == "BLOCKED")
        actual_skipped = sum(1 for cp in cps if isinstance(cp, dict) and cp.get("status") == "SKIPPED")

        self._record(cat, "completed_matches", c == actual_completed,
                     f"Summary completed={c}, actual={actual_completed}")
        self._record(cat, "pending_matches", p == actual_pending,
                     f"Summary pending={p}, actual={actual_pending}")
        self._record(cat, "blocked_matches", b == actual_blocked,
                     f"Summary blocked={b}, actual={actual_blocked}")
        self._record(cat, "skipped_matches", s == actual_skipped,
                     f"Summary skipped={s}, actual={actual_skipped}")

    # ------------------------------------------------------------------
    # 9. Next Steps
    # ------------------------------------------------------------------
    def verify_next_steps(self):
        cat = "next_steps"
        ns = self.report.get("next_steps", [])
        self._record(cat, "is_list", isinstance(ns, list), "next_steps is list")

        if not isinstance(ns, list):
            return

        # Count matches non-completed checkpoints
        cps = self.report.get("checkpoints", [])
        non_completed = sum(1 for cp in cps if isinstance(cp, dict) and cp.get("status") != "COMPLETED")
        self._record(cat, "count_matches", len(ns) == non_completed,
                     f"Next steps: {len(ns)}, non-completed: {non_completed}")

        step_nums = set()
        cp_ids_in_steps = set()
        for i, step in enumerate(ns):
            self._record(cat, f"step_{i}_is_dict", isinstance(step, dict), f"Step {i} is dict")
            if not isinstance(step, dict):
                continue

            for field in NEXT_STEP_REQUIRED:
                self._record(cat, f"step_{i}_has_{field}", field in step,
                             f"Step {i} has {field}" if field in step else f"Step {i} missing {field}")

            # Step number sequential
            sn = step.get("step_number", -1)
            self._record(cat, f"step_{i}_number_correct", sn == i + 1,
                         f"Step {i} number={sn}, expected {i+1}")
            step_nums.add(sn)

            # Priority valid
            pri = step.get("priority", "")
            self._record(cat, f"step_{i}_priority_valid", pri in VALID_PRIORITIES,
                         f"Step {i} priority: {pri}")

            # Checkpoint ID valid
            cp_id = step.get("checkpoint_id", "")
            role = self.report.get("meta", {}).get("role", "")
            valid_ids = set(CONSUMER_IDS if role == "CONSUMER" else PRODUCER_IDS)
            self._record(cat, f"step_{i}_cp_valid", cp_id in valid_ids,
                         f"Step {i} checkpoint: {cp_id}")
            cp_ids_in_steps.add(cp_id)

            # Command non-empty
            cmd = step.get("command", "")
            self._record(cat, f"step_{i}_has_command", len(str(cmd)) > 5,
                         f"Step {i} command length: {len(str(cmd))}")

            # Action non-empty
            action = step.get("action", "")
            self._record(cat, f"step_{i}_has_action", len(str(action)) > 5,
                         f"Step {i} action length: {len(str(action))}")

        # No duplicate step numbers
        self._record(cat, "no_dup_step_nums", len(step_nums) == len(ns),
                     f"Unique step numbers: {len(step_nums)}/{len(ns)}")

        # All non-completed CPs have next steps
        non_completed_ids = {cp.get("checkpoint_id") for cp in cps
                            if isinstance(cp, dict) and cp.get("status") != "COMPLETED"}
        self._record(cat, "all_non_completed_covered", non_completed_ids == cp_ids_in_steps,
                     f"Non-completed covered" if non_completed_ids == cp_ids_in_steps
                     else f"Missing: {non_completed_ids - cp_ids_in_steps}")

    # ------------------------------------------------------------------
    # 10. Verdict
    # ------------------------------------------------------------------
    def verify_verdict(self):
        cat = "verdict"
        v = self.report.get("verdict", {})
        self._record(cat, "is_dict", isinstance(v, dict), "verdict is dict")

        if not isinstance(v, dict):
            return

        for field in VERDICT_REQUIRED:
            self._record(cat, f"has_{field}", field in v,
                         f"Has {field}" if field in v else f"Missing {field}")

        # Readiness valid
        readiness = v.get("readiness", "")
        self._record(cat, "readiness_valid", readiness in VALID_READINESS, f"Readiness: {readiness}")

        # Grade valid
        grade = v.get("grade", "")
        self._record(cat, "grade_valid", grade in VALID_GRADES, f"Grade: {grade}")

        # Completion rate bounds
        cr = v.get("completion_rate", -1)
        self._record(cat, "completion_rate_bounds", 0 <= cr <= 1, f"Completion rate: {cr}")

        # Rationale length
        rat = v.get("rationale", "")
        self._record(cat, "rationale_length", len(str(rat)) >= 10, f"Rationale length: {len(str(rat))}")

        # Recommendation length
        rec = v.get("recommendation", "")
        self._record(cat, "recommendation_length", len(str(rec)) >= 10, f"Recommendation length: {len(str(rec))}")

        # Verdict matches progress
        ps = self.report.get("progress_summary", {})
        ps_readiness = ps.get("readiness", "")
        self._record(cat, "readiness_matches_progress", readiness == ps_readiness,
                     f"Verdict readiness={readiness}, progress readiness={ps_readiness}")

        ps_cr = ps.get("completion_rate", -1)
        self._record(cat, "cr_matches_progress", abs(cr - ps_cr) < 0.001,
                     f"Verdict CR={cr}, progress CR={ps_cr}")

        # Grade consistency with completion rate
        expected_grade = "A" if cr >= 1.0 else "B" if cr >= 0.75 else "C" if cr >= 0.50 else "D" if cr >= 0.25 else "F"
        self._record(cat, "grade_consistent", grade == expected_grade,
                     f"Grade={grade}, expected={expected_grade} for CR={cr}")

    # ------------------------------------------------------------------
    # 11. Hash Chain
    # ------------------------------------------------------------------
    def verify_hash_chain(self):
        cat = "hash_chain"
        hc = self.report.get("hash_chain", {})
        self._record(cat, "is_dict", isinstance(hc, dict), "hash_chain is dict")

        if not isinstance(hc, dict):
            return

        for field in HASH_CHAIN_REQUIRED:
            self._record(cat, f"has_{field}", field in hc,
                         f"Has {field}" if field in hc else f"Missing {field}")

        # Algorithm
        algo = hc.get("algorithm", "")
        self._record(cat, "algorithm_sha256", algo == "SHA-256", f"Algorithm: {algo}")

        # Report hash format
        rh = hc.get("report_hash", "")
        rh_ok = bool(re.match(r"^[0-9a-f]{64}$", str(rh)))
        self._record(cat, "report_hash_format", rh_ok, f"Report hash valid hex-64")

        # Previous hash format (null or hex-64)
        ph = hc.get("previous_report_hash")
        ph_ok = ph is None or bool(re.match(r"^[0-9a-f]{64}$", str(ph)))
        self._record(cat, "previous_hash_format", ph_ok,
                     f"Previous hash: {'null' if ph is None else 'hex-64'}")

    # ------------------------------------------------------------------
    # 12. Content Hash Integrity
    # ------------------------------------------------------------------
    def verify_content_hash_integrity(self):
        cat = "content_hash_integrity"
        meta = self.report.get("meta", {})
        claimed_hash = meta.get("content_hash", "")

        # Recompute content hash using same placeholder approach as scanner
        import copy as _copy
        hashable = {k: v for k, v in self.report.items() if k != "hash_chain"}
        hashable = _copy.deepcopy(hashable)
        if "meta" in hashable and isinstance(hashable["meta"], dict):
            hashable["meta"]["content_hash"] = "0" * 64  # stable placeholder
        computed_hash = sha256_dict(hashable)

        self._record(cat, "content_hash_matches", claimed_hash == computed_hash,
                     f"Content hash matches" if claimed_hash == computed_hash
                     else f"Claimed={claimed_hash[:16]}..., computed={computed_hash[:16]}...")

        # Report hash recomputation
        hc = self.report.get("hash_chain", {})
        claimed_rh = hc.get("report_hash", "")
        computed_rh = sha256_dict(self.report)

        # Note: report_hash includes itself, so we can only verify format
        self._record(cat, "report_hash_hex64", bool(re.match(r"^[0-9a-f]{64}$", str(claimed_rh))),
                     "Report hash is valid hex-64")

        # Verify content hash is non-empty
        self._record(cat, "content_hash_non_empty", len(str(claimed_hash)) == 64,
                     f"Content hash length: {len(str(claimed_hash))}")

    # ------------------------------------------------------------------
    # 13. Limitations
    # ------------------------------------------------------------------
    def verify_limitations(self):
        cat = "limitations"
        lim = self.report.get("limitations", {})
        self._record(cat, "is_dict", isinstance(lim, dict), "limitations is dict")

        if not isinstance(lim, dict):
            return

        self._record(cat, "has_count", "count" in lim, "Has count field")
        self._record(cat, "has_items", "items" in lim, "Has items field")

        items = lim.get("items", [])
        count = lim.get("count", 0)
        self._record(cat, "count_matches", count == len(items) if isinstance(items, list) else False,
                     f"Count={count}, items={len(items) if isinstance(items, list) else 'N/A'}")

        self._record(cat, "items_is_list", isinstance(items, list), "items is list")
        self._record(cat, "has_items_nonzero", len(items) > 0 if isinstance(items, list) else False,
                     f"Has {len(items) if isinstance(items, list) else 0} limitation(s)")

        if isinstance(items, list):
            ids_seen = set()
            for i, item in enumerate(items):
                self._record(cat, f"item_{i}_is_dict", isinstance(item, dict), f"Item {i} is dict")
                if not isinstance(item, dict):
                    continue

                for field in LIMITATION_REQUIRED:
                    self._record(cat, f"item_{i}_has_{field}", field in item,
                                 f"Item {i} has {field}" if field in item else f"Item {i} missing {field}")

                # ID format
                lid = item.get("id", "")
                lid_ok = bool(re.match(r"^LIM-\d{3}$", str(lid)))
                self._record(cat, f"item_{i}_id_format", lid_ok, f"Item {i} id: {lid}")

                # ID unique
                self._record(cat, f"item_{i}_id_unique", lid not in ids_seen,
                             f"Item {i} id unique" if lid not in ids_seen else f"Duplicate: {lid}")
                ids_seen.add(lid)

                # Description length
                desc = item.get("description", "")
                self._record(cat, f"item_{i}_desc_len", len(str(desc)) >= 10,
                             f"Item {i} description length: {len(str(desc))}")

                # Bias direction valid
                bd = item.get("bias_direction", "")
                self._record(cat, f"item_{i}_bias_dir_valid", bd in VALID_BIAS_DIRS,
                             f"Item {i} bias_direction: {bd}")

                # Bias magnitude valid
                bm = item.get("bias_magnitude", "")
                self._record(cat, f"item_{i}_bias_mag_valid", bm in VALID_BIAS_MAGS,
                             f"Item {i} bias_magnitude: {bm}")

    # ------------------------------------------------------------------
    # 14. Cross Consistency
    # ------------------------------------------------------------------
    def verify_cross_consistency(self):
        cat = "cross_consistency"
        meta = self.report.get("meta", {})
        pc = self.report.get("pathway_config", {})
        ps = self.report.get("progress_summary", {})
        verdict = self.report.get("verdict", {})

        # Role consistency across sections
        meta_role = meta.get("role", "")
        pc_role = pc.get("role", "")
        self._record(cat, "role_meta_eq_config", meta_role == pc_role,
                     f"Meta role={meta_role}, config role={pc_role}")

        # Report ID contains correct role
        rid = meta.get("report_id", "")
        if meta_role:
            self._record(cat, "role_in_report_id", meta_role in rid,
                         f"Role {meta_role} in report_id {rid}")

        # Scanner version matches top-level
        sv = self.report.get("scanner_version", "")
        gv = meta.get("generator_version", "")
        self._record(cat, "version_consistency", sv == gv,
                     f"Scanner version={sv}, generator version={gv}")

        # Completion rate across sections
        ps_cr = ps.get("completion_rate", -1)
        v_cr = verdict.get("completion_rate", -2)
        self._record(cat, "cr_progress_eq_verdict", abs(ps_cr - v_cr) < 0.001,
                     f"Progress CR={ps_cr}, verdict CR={v_cr}")

        # Readiness across sections
        ps_r = ps.get("readiness", "")
        v_r = verdict.get("readiness", "")
        self._record(cat, "readiness_progress_eq_verdict", ps_r == v_r,
                     f"Progress readiness={ps_r}, verdict readiness={v_r}")

        # Checkpoint IDs match definitions
        cps = self.report.get("checkpoints", [])
        defs = pc.get("checkpoint_definitions", [])
        cp_ids = [cp.get("checkpoint_id") for cp in cps if isinstance(cp, dict)]
        def_ids = [d.get("checkpoint_id") for d in defs if isinstance(d, dict)]
        self._record(cat, "cp_ids_match_defs", cp_ids == def_ids,
                     f"Checkpoint IDs match definitions" if cp_ids == def_ids
                     else f"Mismatch: {cp_ids} vs {def_ids}")

        # Checkpoint count consistency
        cp_count = len(cps) if isinstance(cps, list) else 0
        config_count = pc.get("checkpoint_count", 0)
        self._record(cat, "cp_count_eq_config", cp_count == config_count,
                     f"Checkpoint count={cp_count}, config={config_count}")

        ps_total = ps.get("total_checkpoints", 0)
        self._record(cat, "cp_count_eq_progress", cp_count == ps_total,
                     f"Checkpoint count={cp_count}, progress total={ps_total}")

        # Next steps only reference non-completed checkpoints
        ns = self.report.get("next_steps", [])
        completed_ids = {cp.get("checkpoint_id") for cp in cps
                        if isinstance(cp, dict) and cp.get("status") == "COMPLETED"}
        for step in ns:
            if isinstance(step, dict):
                sid = step.get("checkpoint_id", "")
                self._record(cat, f"next_step_{sid}_not_completed", sid not in completed_ids,
                             f"Next step {sid} is not completed" if sid not in completed_ids
                             else f"Next step {sid} is already completed")

    # ------------------------------------------------------------------
    # 15. Role Specific
    # ------------------------------------------------------------------
    def verify_role_specific(self):
        cat = "role_specific"
        role = self.report.get("meta", {}).get("role", "")
        cps = self.report.get("checkpoints", [])

        if role == "CONSUMER":
            expected_ids = CONSUMER_IDS
            prefix = "C-"
        elif role == "PRODUCER":
            expected_ids = PRODUCER_IDS
            prefix = "P-"
        else:
            self._record(cat, "role_recognized", False, f"Unknown role: {role}")
            return

        self._record(cat, "role_recognized", True, f"Role: {role}")

        # All expected IDs present
        actual_ids = [cp.get("checkpoint_id") for cp in cps if isinstance(cp, dict)]
        for eid in expected_ids:
            self._record(cat, f"has_{eid}", eid in actual_ids,
                         f"Has {eid}" if eid in actual_ids else f"Missing {eid}")

        # All IDs use correct prefix
        for cp in cps:
            if isinstance(cp, dict):
                cid = cp.get("checkpoint_id", "")
                self._record(cat, f"{cid}_correct_prefix", cid.startswith(prefix),
                             f"{cid} starts with {prefix}" if cid.startswith(prefix)
                             else f"{cid} wrong prefix")

        # Checkpoint order is strictly ascending
        orders = [cp.get("order", 0) for cp in cps if isinstance(cp, dict)]
        is_ascending = all(orders[i] < orders[i+1] for i in range(len(orders)-1)) if len(orders) > 1 else True
        self._record(cat, "order_ascending", is_ascending,
                     f"Orders ascending: {orders}")

        # First checkpoint has no dependencies
        if cps and isinstance(cps[0], dict):
            first_deps = cps[0].get("depends_on", [])
            self._record(cat, "first_no_deps", len(first_deps) == 0,
                         f"First checkpoint deps: {first_deps}")

        # Dependency chain is linear (each depends on previous)
        for i in range(1, len(cps)):
            if isinstance(cps[i], dict) and isinstance(cps[i-1], dict):
                deps = cps[i].get("depends_on", [])
                prev_id = cps[i-1].get("checkpoint_id", "")
                self._record(cat, f"cp_{i}_depends_on_prev", prev_id in deps,
                             f"CP {i} depends on {prev_id}" if prev_id in deps
                             else f"CP {i} does not depend on {prev_id}")

    # ------------------------------------------------------------------
    # 16. Schema Validation
    # ------------------------------------------------------------------
    def verify_schema_validation(self):
        cat = "schema_validation"
        if self.schema is None:
            self._record(cat, "schema_available", False, "No schema provided for validation")
            return

        self._record(cat, "schema_available", True, "Schema loaded for validation")

        # Check schema has required structure
        self._record(cat, "schema_has_defs", "$defs" in self.schema, "Schema has $defs")
        self._record(cat, "schema_has_required", "required" in self.schema, "Schema has required")
        self._record(cat, "schema_has_properties", "properties" in self.schema, "Schema has properties")

        # Check all $defs present
        expected_defs = [
            "scan_meta", "pathway_config", "checkpoint_def", "checkpoint",
            "checkpoint_validation", "progress_summary", "next_step",
            "scan_verdict", "hash_chain", "limitation", "limitations"
        ]
        defs = self.schema.get("$defs", {})
        for d in expected_defs:
            self._record(cat, f"def_{d}_exists", d in defs,
                         f"$defs has {d}" if d in defs else f"$defs missing {d}")

        # Check schema required matches REQUIRED_TOP_LEVEL
        schema_req = self.schema.get("required", [])
        for field in REQUIRED_TOP_LEVEL:
            self._record(cat, f"schema_requires_{field}", field in schema_req,
                         f"Schema requires {field}" if field in schema_req else f"Schema missing required {field}")

        # Verify enum values in schema match constants
        # Status enum
        cp_def = defs.get("checkpoint", {})
        cp_props = cp_def.get("properties", {})
        status_enum = cp_props.get("status", {}).get("enum", [])
        for s in VALID_STATUSES:
            self._record(cat, f"status_enum_has_{s}", s in status_enum,
                         f"Status enum has {s}")

        # Readiness enum
        ps_def = defs.get("progress_summary", {})
        ps_props = ps_def.get("properties", {})
        readiness_enum = ps_props.get("readiness", {}).get("enum", [])
        for r in VALID_READINESS:
            self._record(cat, f"readiness_enum_has_{r}", r in readiness_enum,
                         f"Readiness enum has {r}")

        # Grade enum
        sv_def = defs.get("scan_verdict", {})
        sv_props = sv_def.get("properties", {})
        grade_enum = sv_props.get("grade", {}).get("enum", [])
        for g in VALID_GRADES:
            self._record(cat, f"grade_enum_has_{g}", g in grade_enum,
                         f"Grade enum has {g}")

        # Role enum
        meta_def = defs.get("scan_meta", {})
        meta_props = meta_def.get("properties", {})
        role_enum = meta_props.get("role", {}).get("enum", [])
        for r in VALID_ROLES:
            self._record(cat, f"role_enum_has_{r}", r in role_enum,
                         f"Role enum has {r}")

        # Bias direction enum
        lim_def = defs.get("limitation", {})
        lim_props = lim_def.get("properties", {})
        bd_enum = lim_props.get("bias_direction", {}).get("enum", [])
        for b in VALID_BIAS_DIRS:
            self._record(cat, f"bias_dir_enum_has_{b}", b in bd_enum,
                         f"Bias direction enum has {b}")

    # ------------------------------------------------------------------
    # Results
    # ------------------------------------------------------------------
    def get_results(self):
        """Return verification results."""
        total = len(self.checks)
        passed = sum(1 for c in self.checks if c["passed"])
        failed = total - passed
        pass_rate = round(passed / total, 4) if total > 0 else 0.0

        return {
            "total_checks": total,
            "passed": passed,
            "failed": failed,
            "pass_rate": pass_rate,
            "grade": "A" if pass_rate >= 0.95 else "B" if pass_rate >= 0.85 else "C" if pass_rate >= 0.70 else "D" if pass_rate >= 0.50 else "F",
            "categories": self.categories,
            "checks": self.checks,
            "failures": [c for c in self.checks if not c["passed"]]
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) < 2:
        print("Usage: python3 verify_pathway.py <report.json> [report2.json ...] [--schema schema.json]", file=sys.stderr)
        sys.exit(1)

    # Parse args
    report_files = []
    schema_file = None
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == "--schema" and i + 1 < len(sys.argv):
            schema_file = sys.argv[i + 1]
            i += 2
        else:
            report_files.append(sys.argv[i])
            i += 1

    # Load schema if provided
    schema = None
    if schema_file:
        try:
            with open(schema_file) as f:
                schema = json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            print(f"Warning: Could not load schema: {e}", file=sys.stderr)

    # Auto-detect schema
    if schema is None:
        schema_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "onboarding_pathway_schema.json")
        if os.path.exists(schema_path):
            try:
                with open(schema_path) as f:
                    schema = json.load(f)
            except (IOError, json.JSONDecodeError):
                pass

    total_checks = 0
    total_passed = 0
    all_results = []

    for report_file in report_files:
        try:
            with open(report_file) as f:
                report = json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            print(f"Error loading {report_file}: {e}", file=sys.stderr)
            continue

        verifier = PathwayVerifier(report, schema=schema)
        results = verifier.verify_all()
        all_results.append({"file": report_file, "results": results})

        total_checks += results["total_checks"]
        total_passed += results["passed"]

        # Print summary
        role = report.get("meta", {}).get("role", "unknown")
        print(f"\n{'='*60}")
        print(f"Report: {report_file}")
        print(f"Role: {role}")
        print(f"Checks: {results['passed']}/{results['total_checks']} passed ({results['pass_rate']:.1%})")
        print(f"Grade: {results['grade']}")
        print(f"{'='*60}")

        # Category breakdown
        print(f"\nCategory Breakdown:")
        for cat_name, cat_data in sorted(results["categories"].items()):
            status = "PASS" if cat_data["failed"] == 0 else "FAIL"
            print(f"  [{status}] {cat_name}: {cat_data['passed']}/{cat_data['total']} "
                  f"({cat_data['passed']/cat_data['total']:.0%})")

        # Failures
        if results["failures"]:
            print(f"\nFailures ({len(results['failures'])}):")
            for f in results["failures"][:20]:
                print(f"  [{f['category']}] {f['check_name']}: {f['detail']}")
            if len(results["failures"]) > 20:
                print(f"  ... and {len(results['failures']) - 20} more")

    # Grand total
    if len(report_files) > 1:
        grand_rate = round(total_passed / total_checks, 4) if total_checks > 0 else 0.0
        print(f"\n{'='*60}")
        print(f"GRAND TOTAL: {total_passed}/{total_checks} checks passed ({grand_rate:.1%})")
        print(f"{'='*60}")

    return 0 if total_passed == total_checks else 1


if __name__ == "__main__":
    sys.exit(main())
