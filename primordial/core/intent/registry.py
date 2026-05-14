from __future__ import annotations

from pathlib import Path
from typing import Any

from primordial.core.catalog.loader import CatalogValidationError, expect_bool, load_yaml_file, validate_allowed_fields
from primordial.core.intent.models import CredentialPolicy, KerberosPolicy, LabPolicy, OperatorIntent, OperatorIntentPolicy


class OperatorIntentRegistry:
    DEFAULT_INTENT_ID = "recon_only"
    FIELDS = {"id", "label", "description", "policy"}
    POLICY_FIELDS = {
        "public_poc_research",
        "searchsploit_allowed",
        "read_poc_examples",
        "poc_applicability_validation",
        "exploit_code_generation",
        "poc_execution",
        "kerberos_policy",
        "credential_policy",
        "lab_policy",
    }
    KERBEROS_FIELDS = {"asrep_roast_check_allowed", "kerberoast_check_allowed"}
    CREDENTIAL_FIELDS = {
        "credential_validation_allowed",
        "credential_guessing_allowed",
        "credential_spraying_allowed",
        "hash_cracking_allowed",
    }
    LAB_FIELDS = {"lab_flag_collection_allowed", "htb_lab_behavior_allowed", "reverse_shell_allowed"}

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self._intents: dict[str, OperatorIntent] = {}

    def load(self) -> list[OperatorIntent]:
        loaded = []
        if not self.directory.exists():
            return loaded
        for path in sorted(self.directory.glob("*.yaml")):
            intent = self._from_payload(load_yaml_file(path), source=str(path))
            self._intents[intent.id] = intent
            loaded.append(intent)
        if self.DEFAULT_INTENT_ID not in self._intents:
            raise CatalogValidationError(f"missing required default intent: {self.DEFAULT_INTENT_ID}")
        return loaded

    def all(self) -> list[OperatorIntent]:
        return sorted(self._intents.values(), key=lambda item: item.id)

    def get(self, intent_id: str | None) -> OperatorIntent:
        selected = str(intent_id or self.DEFAULT_INTENT_ID).strip() or self.DEFAULT_INTENT_ID
        intent = self._intents.get(selected)
        if intent is None:
            raise KeyError(f"unknown operator intent: {selected}")
        return intent

    def _from_payload(self, payload: dict[str, Any], *, source: str) -> OperatorIntent:
        validate_allowed_fields(payload, self.FIELDS, source=source)
        policy_payload = payload.get("policy", {})
        if not isinstance(policy_payload, dict):
            raise CatalogValidationError(f"{source}.policy must be an object")
        return OperatorIntent(
            id=str(payload["id"]),
            label=str(payload["label"]),
            description=str(payload.get("description", "")),
            policy=self._policy(policy_payload, source=f"{source}.policy"),
        )

    def _policy(self, payload: dict[str, Any], *, source: str) -> OperatorIntentPolicy:
        validate_allowed_fields(payload, self.POLICY_FIELDS, source=source)
        kerberos = self._nested(payload.get("kerberos_policy", {}), self.KERBEROS_FIELDS, source=f"{source}.kerberos_policy")
        credential = self._nested(payload.get("credential_policy", {}), self.CREDENTIAL_FIELDS, source=f"{source}.credential_policy")
        lab = self._nested(payload.get("lab_policy", {}), self.LAB_FIELDS, source=f"{source}.lab_policy")
        return OperatorIntentPolicy(
            public_poc_research=expect_bool(payload.get("public_poc_research"), source=f"{source}.public_poc_research"),
            searchsploit_allowed=expect_bool(payload.get("searchsploit_allowed"), source=f"{source}.searchsploit_allowed"),
            read_poc_examples=expect_bool(payload.get("read_poc_examples"), source=f"{source}.read_poc_examples"),
            poc_applicability_validation=expect_bool(
                payload.get("poc_applicability_validation"),
                source=f"{source}.poc_applicability_validation",
            ),
            exploit_code_generation=expect_bool(payload.get("exploit_code_generation"), source=f"{source}.exploit_code_generation"),
            poc_execution=expect_bool(payload.get("poc_execution"), source=f"{source}.poc_execution"),
            kerberos_policy=KerberosPolicy(
                asrep_roast_check_allowed=expect_bool(
                    kerberos.get("asrep_roast_check_allowed"),
                    source=f"{source}.kerberos_policy.asrep_roast_check_allowed",
                ),
                kerberoast_check_allowed=expect_bool(
                    kerberos.get("kerberoast_check_allowed"),
                    source=f"{source}.kerberos_policy.kerberoast_check_allowed",
                ),
            ),
            credential_policy=CredentialPolicy(
                credential_validation_allowed=expect_bool(
                    credential.get("credential_validation_allowed"),
                    source=f"{source}.credential_policy.credential_validation_allowed",
                ),
                credential_guessing_allowed=expect_bool(
                    credential.get("credential_guessing_allowed"),
                    source=f"{source}.credential_policy.credential_guessing_allowed",
                ),
                credential_spraying_allowed=expect_bool(
                    credential.get("credential_spraying_allowed"),
                    source=f"{source}.credential_policy.credential_spraying_allowed",
                ),
                hash_cracking_allowed=expect_bool(
                    credential.get("hash_cracking_allowed"),
                    source=f"{source}.credential_policy.hash_cracking_allowed",
                ),
            ),
            lab_policy=LabPolicy(
                lab_flag_collection_allowed=expect_bool(
                    lab.get("lab_flag_collection_allowed"),
                    source=f"{source}.lab_policy.lab_flag_collection_allowed",
                ),
                htb_lab_behavior_allowed=expect_bool(
                    lab.get("htb_lab_behavior_allowed"),
                    source=f"{source}.lab_policy.htb_lab_behavior_allowed",
                ),
                reverse_shell_allowed=expect_bool(
                    lab.get("reverse_shell_allowed"),
                    source=f"{source}.lab_policy.reverse_shell_allowed",
                ),
            ),
        )

    def _nested(self, payload: Any, allowed: set[str], *, source: str) -> dict[str, Any]:
        if payload is None:
            return {}
        if not isinstance(payload, dict):
            raise CatalogValidationError(f"{source} must be an object")
        validate_allowed_fields(payload, allowed, source=source)
        return payload
