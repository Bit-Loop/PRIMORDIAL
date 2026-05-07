from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True, frozen=True)
class KerberosPolicy:
    asrep_roast_check_allowed: bool = False
    kerberoast_check_allowed: bool = False

    def as_payload(self) -> dict[str, bool]:
        return {
            "asrep_roast_check_allowed": self.asrep_roast_check_allowed,
            "kerberoast_check_allowed": self.kerberoast_check_allowed,
        }


@dataclass(slots=True, frozen=True)
class CredentialPolicy:
    credential_validation_allowed: bool = False
    credential_guessing_allowed: bool = False
    credential_spraying_allowed: bool = False
    hash_cracking_allowed: bool = False

    def as_payload(self) -> dict[str, bool]:
        return {
            "credential_validation_allowed": self.credential_validation_allowed,
            "credential_guessing_allowed": self.credential_guessing_allowed,
            "credential_spraying_allowed": self.credential_spraying_allowed,
            "hash_cracking_allowed": self.hash_cracking_allowed,
        }


@dataclass(slots=True, frozen=True)
class LabPolicy:
    lab_flag_collection_allowed: bool = False
    htb_lab_behavior_allowed: bool = False

    def as_payload(self) -> dict[str, bool]:
        return {
            "lab_flag_collection_allowed": self.lab_flag_collection_allowed,
            "htb_lab_behavior_allowed": self.htb_lab_behavior_allowed,
        }


@dataclass(slots=True, frozen=True)
class OperatorIntentPolicy:
    public_poc_research: bool = False
    searchsploit_allowed: bool = False
    read_poc_examples: bool = False
    poc_applicability_validation: bool = False
    exploit_code_generation: bool = False
    poc_execution: bool = False
    kerberos_policy: KerberosPolicy = field(default_factory=KerberosPolicy)
    credential_policy: CredentialPolicy = field(default_factory=CredentialPolicy)
    lab_policy: LabPolicy = field(default_factory=LabPolicy)

    def allows_permission(self, permission: str) -> bool:
        parts = permission.split(".")
        value: Any = self
        for part in parts:
            value = getattr(value, part, None)
        return bool(value)

    def as_payload(self) -> dict[str, Any]:
        return {
            "public_poc_research": self.public_poc_research,
            "searchsploit_allowed": self.searchsploit_allowed,
            "read_poc_examples": self.read_poc_examples,
            "poc_applicability_validation": self.poc_applicability_validation,
            "exploit_code_generation": self.exploit_code_generation,
            "poc_execution": self.poc_execution,
            "kerberos_policy": self.kerberos_policy.as_payload(),
            "credential_policy": self.credential_policy.as_payload(),
            "lab_policy": self.lab_policy.as_payload(),
        }


@dataclass(slots=True, frozen=True)
class OperatorIntent:
    id: str
    label: str
    description: str
    policy: OperatorIntentPolicy

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "description": self.description,
            "policy": self.policy.as_payload(),
        }
