# Operator Intent

Operator Intent is the durable control surface between chat and tasks. The active intent is stored on the active session at `metadata["operator_intent_id"]`. If no session intent is set, Primordial falls back to `recon_only`.

The web API exposes:

- `GET /api/operator-intent`
- `POST /api/operator-intent` with `{"intent_id": "htb_lab"}`

Baseline intents live under `catalog/intents/` and are strict YAML manifests. Unknown fields are rejected.

Current baseline intents:

- `recon_only`: low-risk discovery and evidence review only.
- `web_triage`: low-risk web review and classification.
- `ad_lab`: compatibility id for authorized in-house AD attack-path checks. In this catalog, "lab" does not mean HTB-style behavior or flag collection.
- `htb_lab`: explicit lab behavior, public PoC research, controlled credential validation, and lab flag collection.
- `credential_validation`: generic known-credential validation only. It does not imply HTB/lab behavior, guessing, spraying, cracking, or flag collection.
- `exploit_research_allowed`: public exploit research and PoC applicability review without execution or exploit-code generation.

Scope profile is not intent. A `hack_the_box` target no longer enables research-heavy or lab-only behavior by itself.

Kerberos attack-path permissions are split. `kerberos_policy.asrep_roast_check_allowed` only permits AS-REP roast applicability checks against discovered principals. `kerberos_policy.kerberoast_check_allowed` only permits SPN-backed Kerberoast candidate review. Hash cracking remains separately disallowed unless a future explicit policy allows it.

Credential validation uses the generic `known` credential namespace. The older `lab` namespace remains a compatibility alias during migration, but production planning and execution should describe these as operator-provided known credentials, not HTB credentials.
