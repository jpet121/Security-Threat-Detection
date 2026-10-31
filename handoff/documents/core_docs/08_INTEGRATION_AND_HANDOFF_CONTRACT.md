# 08 — Integration and handoff

## Boundaries and producer/consumer roles
Producer 1: operator-supplied original local evidence and configured rules. Consumer 1: Python auditor; must preserve evidence and selected-source enumeration, interpret only supported layouts and document parser assumptions. Producer 2: auditor staged findings/summary/manifest. Consumer 2: human analyst; may use results as leads, but must not infer a breach or one attacker from superficial correlation. Producer 3: this PEHAVOS Codex source-frozen handoff. Consumer 3: Codex implementing from the original XML and its compiled requirement index; sources outrank derived design.

## Authority, identity and replay
Application XML SHA-256 `a90d78b46bd2faccc00e3bad1704babcf1eb1b874f0fae09fe7b1578b41ac050`; compiler receipt matches. All 92 mandatory/prohibited propositions traced to Rxxx/Axxx and frozen scenario classes. Handoff archive includes full immutable XML, index, ABVOS 15+7, engineering, Auditor, tests, policy, executable coverage gate and manifest hashes. No Codex changes permitted to source XML, frozen oracles or policy to manufacture passing evidence. Implementation changes allowed only to documented source directories, controlled with a diff and version notes. Cross-boundary IDs must remain joinable.

## Test and execution contract
Codex proceeds in task order TASK-01–TASK-13, designs concrete seams first, executes meaningful `unittest` and `coverage.py` after each increment for 100% executable first-party `.py` line coverage; branch is measured and reviewed, not universally required to 100%; no `unittest.mock`, `patch`, `MagicMock`, pytest monkeypatch or equivalents. After the coverage gate PASSES, perform the 21 applicable disciplines and high-assurance independent recheck against exactly returned archive in a clean approved execution environment. PEHAVOS handoff passing is **preimplementation preparation only**.

## Consumer inferences / failure rules
A source hash identifies the original physical selected file; a source line/range locates a finding; a matching rule is a *suspected* indicator, not evidence of exploitation. Time correlation cannot prove identity. An unknown timestamp cannot be placed precisely among known UTC events. A run with unreadable source cannot be presented as complete. Mismatched XML/test/doc/coverage hashes invalidate the handoff and require repair/reseal. Human release authority remains separate.

## Compatibility / independence constraints
No actual production logs or client analyst labels were available; final acceptance evidence is pending, not an owner-only semantic blocker for design. Future independent reviewer must use separate code review and execute exact returned bytes; current same-host Challenger role is not organizational independence.

---
**Authority:** immutable compiled PFContract XML, SHA-256 `a90d78b46bd2faccc00e3bad1704babcf1eb1b874f0fae09fe7b1578b41ac050`, released compiler receipt status `COMPILE_RELEASED` hash-matched. All P001–P098 retained in `source/REQUIREMENT_INDEX.json`; 92 mandatory/prohibited propositions have exact 1:1 Rxxx/Axxx trace in `analysis/ENGINEERING_REVIEW.json`. Optional/informational P051, P067, P071, P096–P098 remain advisory context, not silently promoted to required behavior. Original full client narrative is not separately available. **Status:** pre-Codex design only; no target application or acceptance test executed; human release approval NOT_GRANTED.
