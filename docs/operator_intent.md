# Operator Intent

Operator Intent is the durable control surface between chat and tasks. The active intent is stored on the active session at `metadata["operator_intent_id"]`. If no session intent is set, Primordial falls back to `recon_only`.

The web API exposes:

- `GET /api/operator-intent`
- `POST /api/operator-intent` with `{"intent_id": "htb_lab"}`

Baseline intents live under `catalog/intents/` and are strict YAML manifests. Unknown fields are rejected.

Current baseline intents:

- `recon_only`: low-risk discovery and evidence review only.
- `web_triage`: low-risk web review and classification.
- `ad_lab`: AD discovery plus selected Kerberos checks.
- `htb_lab`: explicit lab behavior, public PoC research, controlled credential validation, and lab flag collection.
- `credential_validation`: known-credential validation only.
- `exploit_research_allowed`: public exploit research and PoC applicability review without execution or exploit-code generation.

Scope profile is not intent. A `hack_the_box` target no longer enables research-heavy or lab-only behavior by itself.
