# Method selection — risk-based, coverage-first staged verification

## Project profile
Requirement stability: frozen 98 compiled propositions with 92 normative. Consequence of error: misdirected incident response, missed malicious leads, privacy breach, evidence-integrity loss. Interfaces: limited local filesystem, CLI, rules and report artifacts; no network service. Uncertainty: real application-log formats, analyst labels, time provenance and unquantified scaling. Tests can be wholly synthetic for development, but production sensitivity/false positives require real labeled examples.

## Selected lifecycle
Dependency-ordered incremental Python implementation with pure core / filesystem-seam architecture, early `unittest` + `coverage.py` **100% executable first-party line** gate on every code increment, followed by stage-gated independent high assurance. Branch coverage measured and reviewed; no universal 100% branch gate. No framework mocking or dynamic patching. Implement working real adapters and concrete substitute readers/clocks for focused tests. Freeze source-driven acceptance before implementation; never make the implementation define the oracle.

## Verification selection and rationale
Use Feynman-inspired falsification (benign punctuation/401 counterexamples), Hypothesis generative malformed lines/encoded queries, stateful lifecycle for partial/final states, differential HTTP/syslog parser checks and bounded Lean model for partition/count consistency. LIGO-inspired independent confirmation means independent heldout analyst labels and controlled injection of known synthetic audit cases—not LIGO physics hardware. Mutation and fault injection target classification/report failure semantics; stress tests measure RSS/throughput; clean replay verifies packaging.

## Alternatives and reevaluation
Reject waterfall-only with late assurance (would hide bad semantics) and full service/SIEM integration (over-scope). Reject `unittest.mock` despite easy fixtures because v1.2 explicitly prohibits mocking/patching. If new real formats contradict parser assumptions, update tests via controlled owner-approved change, preserve prior regression cases, and rerun entire gate on updated exact code.

---
**Authority:** immutable compiled PFContract XML, SHA-256 `a90d78b46bd2faccc00e3bad1704babcf1eb1b874f0fae09fe7b1578b41ac050`, released compiler receipt status `COMPILE_RELEASED` hash-matched. All P001–P098 retained in `source/REQUIREMENT_INDEX.json`; 92 mandatory/prohibited propositions have exact 1:1 Rxxx/Axxx trace in `analysis/ENGINEERING_REVIEW.json`. Optional/informational P051, P067, P071, P096–P098 remain advisory context, not silently promoted to required behavior. Original full client narrative is not separately available. **Status:** pre-Codex design only; no target application or acceptance test executed; human release approval NOT_GRANTED.
