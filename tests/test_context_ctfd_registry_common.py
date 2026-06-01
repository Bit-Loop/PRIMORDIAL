from __future__ import annotations

import unittest

from primordial.core.context import ContextEnvelope, ContextSinkValidator

class CTFdRegistrySinkTestsBase(unittest.TestCase):
    def _registry_envelope(
        self,
        ref: str,
        *,
        kind: str = "ctfd_ref",
        authority: str = "asserted",
        **metadata: object,
    ) -> ContextEnvelope:
        record_metadata = {
            "record_type": "challenge_metadata",
            "challenge_id": ref.removeprefix("ctfd:"),
        }
        record_metadata.update(metadata)
        return ContextEnvelope(
            ref=ref,
            kind=kind,
            authority=authority,
            source_type="ctfd",
            purpose="ctf_benchmark",
            sink="ctfd_registry",
            content="CTFd registry record must remain scoreboard metadata only.",
            citations=["ctfd:challenge-101"],
            metadata=record_metadata,
        )

    def _submission_envelope(self, ref: str, *, kind: str, authority: str = "asserted") -> ContextEnvelope:
        return ContextEnvelope(
            ref=ref,
            kind=kind,
            authority=authority,
            source_type="ctfd",
            purpose="ctf_benchmark",
            sink="ctfd_submission",
            content="CTFd submission records must not create authority objects.",
            citations=["ctfd:challenge-101"],
            metadata={
                "active_intent": "ctf_solve_assisted",
                "record_type": "submission_result",
                "challenge_id": ref.removeprefix("ctfd:submission-"),
            },
        )

__all__ = [name for name in globals() if not name.startswith("__")]
