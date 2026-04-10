# pf-onboarding-pathway

Canonical Onboarding Pathway Scanner for the Post Fiat protocol ecosystem.

New users face 22+ repos with no way to know where they are in the integration journey. This pack models two ordered pathways (PRODUCER and CONSUMER), scans artifacts, validates checkpoints, and outputs a dated readiness report with exact next-step commands.

## Quick Start

```bash
# Scan producer readiness
python3 scan_pathway.py --role PRODUCER \
  --signal-sample signals.json \
  --proof-surface proof_surface.json \
  --health-report health.json \
  --trust-eval trust.json \
  --activity-feed feed.json \
  --discovery-result discovery.json \
  -o producer_report.json --summary

# Scan consumer readiness
python3 scan_pathway.py --role CONSUMER \
  --discovery-result discovery.json \
  --signal-sample signals.json \
  --trust-eval trust.json \
  --acceptance-report acceptance.json \
  --activity-feed feed.json \
  --verification-report verification.json \
  --health-report health.json \
  -o consumer_report.json --summary

# Verify reports (zero-trust, 16 categories, 800+ checks)
python3 verify_pathway.py producer_report.json consumer_report.json --schema onboarding_pathway_schema.json

# Run tests
python3 -m pytest tests/test_pathway.py -v
```

## Pathways

### CONSUMER (8 checkpoints)

| Order | Checkpoint | Protocol | Depends On |
|-------|-----------|----------|------------|
| 1 | C-DISCOVERY | pf-discovery-protocol | — |
| 2 | C-SCHEMA | pf-signal-schema | C-DISCOVERY |
| 3 | C-ROUTING | pf-routing-protocol | C-SCHEMA |
| 4 | C-TRUST | pf-trust-gateway | C-ROUTING |
| 5 | C-ACCEPTANCE | pf-acceptance-test | C-TRUST |
| 6 | C-CONSUMPTION | pf-consumer-activity-feed | C-ACCEPTANCE |
| 7 | C-VERIFICATION | pf-consumer-verification | C-CONSUMPTION |
| 8 | C-MONITORING | pf-health-monitor | C-VERIFICATION |

### PRODUCER (8 checkpoints)

| Order | Checkpoint | Protocol | Depends On |
|-------|-----------|----------|------------|
| 1 | P-SCHEMA | pf-signal-schema | — |
| 2 | P-DELIVERY | pf-signal-schema | P-SCHEMA |
| 3 | P-RESOLUTION | pf-resolution-protocol | P-DELIVERY |
| 4 | P-PROOF | pf-proof-protocol | P-RESOLUTION |
| 5 | P-DISCOVERY | pf-discovery-protocol | P-PROOF |
| 6 | P-HEALTH | pf-health-monitor | P-DISCOVERY |
| 7 | P-TRUST | pf-trust-gateway | P-HEALTH |
| 8 | P-ACTIVITY | pf-consumer-activity-feed | P-TRUST |

## Report Structure

9 top-level fields: `scanner_version`, `meta`, `pathway_config`, `checkpoints`, `progress_summary`, `next_steps`, `verdict`, `hash_chain`, `limitations`

### Checkpoint Statuses
- **COMPLETED** — all validation checks pass and dependencies met
- **PENDING** — not yet validated (artifact missing or checks failing)
- **BLOCKED** — dependency checkpoint not COMPLETED
- **SKIPPED** — explicitly skipped

### Readiness Verdicts
- **READY** — 8/8 checkpoints completed
- **NEARLY_READY** — 6-7/8 completed
- **IN_PROGRESS** — 1-5/8 completed
- **NOT_STARTED** — 0/8 completed
- **BLOCKED** — any checkpoint blocked by unmet dependency

### Grades
A (100%) / B (75%+) / C (50%+) / D (25%+) / F (<25%)

## Verification

16 verification categories, 1672 checks across both example reports:

| Category | Description |
|----------|-------------|
| structure | Top-level fields, no extras |
| version | Scanner version semver |
| meta | Report ID format, content hash, timestamps |
| pathway_config | Role, checkpoint definitions, ordering |
| checkpoints_structure | 8 checkpoints, required fields, status enums |
| checkpoint_validations | Arithmetic, pass rates, detail structure |
| dependencies | DAG validity, no cycles, blocked_by consistency |
| progress_summary | Counts sum to 8, matches checkpoint statuses |
| next_steps | Sequential numbering, valid priorities, commands |
| verdict | Readiness/grade consistency with progress |
| hash_chain | SHA-256 format, algorithm constant |
| content_hash_integrity | Recomputed hash matches claimed |
| limitations | LIM-NNN format, bias direction/magnitude |
| cross_consistency | Role agreement across sections |
| role_specific | Correct prefix, linear dependency chain |
| schema_validation | All $defs present, enum values match |

## Tests

152 tests across 12 categories:

```
TestSchemaStructure        16 tests  — JSON Schema structure
TestCheckpointDefinitions  10 tests  — Checkpoint DAGs
TestConsumerValidators     24 tests  — Consumer checkpoint validators
TestProducerValidators     24 tests  — Producer checkpoint validators
TestDependencyPropagation  10 tests  — Status propagation
TestReportBuilder          15 tests  — Report generation
TestVerdictLogic           10 tests  — Grading and readiness
TestVerifier                6 tests  — Zero-trust verifier
TestMalformedInputs        12 tests  — Error handling
TestNextStepCommands        8 tests  — Command generation
TestCLI                     4 tests  — CLI invocation
TestEdgeCases              12 tests  — Boundary conditions
```

## Limitations

| ID | Description | Bias | Magnitude |
|----|-------------|------|-----------|
| LIM-001 | Validates structure, not live network connectivity | OVERSTATED_READINESS | MEDIUM |
| LIM-002 | Checks JSON structure, not full protocol validation | OVERSTATED_READINESS | LOW |
| LIM-003 | Strict BLOCKED may understate partial progress | UNDERSTATED_READINESS | LOW |
| LIM-004 | No temporal consistency validation between artifacts | OVERSTATED_READINESS | MEDIUM |
| LIM-005 | Next-step commands use template paths | INDETERMINATE | LOW |
| LIM-006 | Hash chain requires multiple scans for integrity | INDETERMINATE | LOW |

## Zero Dependencies

All tools use Python 3 stdlib only. No pip install required.
