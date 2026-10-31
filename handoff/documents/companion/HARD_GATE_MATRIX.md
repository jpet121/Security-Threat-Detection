# Hard gate matrix — scope-specific status

| Gate | Pre-Codex state | Later app requirement | Reason / evidence |
|---|---|---|---|
| Compiler/source authority | PASS for identity | Preserve identical bytes | XML SHA-256 `a90d78b46bd2faccc00e3bad1704babcf1eb1b874f0fae09fe7b1578b41ac050` matches receipt |
| Normative trace | DESIGNED (92/92) | Execute traced acceptance | Rxxx/Axxx for all P-required/prohibited |
| Domain semantics | REVIEWED DESIGN | Prove positive and neighbor tests | S01–S36 source-derived corpus |
| Architecture and interfaces | REVIEWED DESIGN | Implement and exercise adapters | documents 03–09, TASK-01–13 |
| Security/privacy | PROSPECTIVE | Test source immutability/redaction/no-network | S11/S19/S25/S26/S27 |
| Verification coverage | POLICY SEALED | 100% all first-party executable line coverage | codex executable gate; branch measured/reviewed |
| Independent high assurance | PENDING | Execute 21 applicability disciplines | Hypothesis/Lean/fuzz/mutation/fault/clean replay |
| Labeled client data | FUTURE REQUIRED | Evaluate precision/recall and analyst agreement | P072/P083–P090 |
| Busy-weekend benchmark | FUTURE REQUIRED | Report elapsed/RSS/scale | P085/P086 |
| Final artifact/release | NOT GRANTED | Return source ZIP, independent recheck, human approval | P087–P094; no release delegation |

## No aggregation of failed gates
Do not turn an uncovered P-id, a mismatched source hash, an unreadable selected file, a leaked token, a skipped no-mock check or a false application PASS into a score tradeoff. Current preimplementation status is design/trace ready only; `audit-job` and ZIP `verify-handoff` are separately executed tools and their actual output is decisive for handoff delivery. Future application gates remain unmet regardless of this handoff status.

---
**Authority:** immutable compiled PFContract XML, SHA-256 `a90d78b46bd2faccc00e3bad1704babcf1eb1b874f0fae09fe7b1578b41ac050`, released compiler receipt status `COMPILE_RELEASED` hash-matched. All P001–P098 retained in `source/REQUIREMENT_INDEX.json`; 92 mandatory/prohibited propositions have exact 1:1 Rxxx/Axxx trace in `analysis/ENGINEERING_REVIEW.json`. Optional/informational P051, P067, P071, P096–P098 remain advisory context, not silently promoted to required behavior. Original full client narrative is not separately available. **Status:** pre-Codex design only; no target application or acceptance test executed; human release approval NOT_GRANTED.
