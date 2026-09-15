# File-only core walkthrough

This walkthrough exercises the assisted rehearsal CLI with committed synthetic
inputs. It starts no broker or native runtime, sends no message, reads no user
configuration or transcript, and performs no dialogue or capture deletion. Its
calculated G1 `pass` tests evaluator behavior only; it is not evidence that G1 or
any other live gate ran.

The maintainer supplies an absolute, existing, empty work directory. The script
keeps the generated inputs, private run, proof-ineligible export, and result for
inspection:

```sh
WALKTHROUGH_ROOT="$(mktemp -d)"
python3 examples/live-rehearsal/core-walkthrough/walkthrough.py \
  --workspace "$WALKTHROUGH_ROOT"
```

The script uses `scenario.json`, `support.txt`, and the independent
`scripts/fixtures/live_rehearsal/named-g1-pass.fixture.json` record. The repeated
hexadecimal source object IDs in `scenario.json` are deliberately fictitious and
do not identify a tested release. The script writes the exact strict plan, import,
and checkpoint inputs under `$WALKTHROUGH_ROOT/inputs/`, then invokes the same
commands a maintainer uses:

1. `init` creates `$WALKTHROUGH_ROOT/run` exclusively.
2. `import-evidence` copies the selected synthetic support file and returns its
   random opaque evidence ref.
3. `checkpoint --preview` checks the frozen declaration without writing state;
   the same checkpoint then records `plan_frozen`.
4. Further checkpoints record authorization, arm the declared case, establish
   the first attempt boundary with an unobserved record, seal the synthetic
   observation, and make assessment ready.
5. `validate` checks record structure and every indexed object. `assess`
   recomputes the declared result.
6. `export --fixture-artifacts` creates a `rehearsal-fixture-export/v1` inventory,
   `fixture-record.json`, and `rehearsal-fixture-summary/v1`. All three state
   `proof_eligible: false` directly or through the fixed synthetic limitation.
   Fixture mode without `--fixture-artifacts` refuses export.
7. The final checkpoints verify the exact export-manifest digest and record
   cleanup as skipped. They perform no cleanup action. The resulting state is
   `cleanup_recorded` because the skipped outcomes were recorded explicitly.

Successful output resembles:

```json
{
  "calculated_result": "pass",
  "context_kind": "fixture",
  "evidence_items_verified": 1,
  "export_format": "rehearsal-fixture-export/v1",
  "format": "rehearsal-core-walkthrough-result/v1",
  "live_actions_performed": [],
  "proof_eligible": false,
  "record_valid": true,
  "runner_state": "cleanup_recorded",
  "workspace_retained": "/absolute/operator-selected/path"
}
```

The maintainer inspects the retained files and removes that explicitly selected
temporary directory when it is no longer needed. The runner itself never removes
run or export evidence.
