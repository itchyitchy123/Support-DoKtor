from __future__ import annotations

from abc import ABC, abstractmethod

from support_doctor.context import InvestigationContext
from support_doctor.models import Incident, RecoveryPlan, Severity


class DiagnosticModule(ABC):
    name: str

    @abstractmethod
    def inspect(self, context: InvestigationContext) -> list[Incident]:
        raise NotImplementedError

    def plan(self, context: InvestigationContext) -> list[Incident]:
        incidents = self.inspect(context)
        for incident in incidents:
            incident.plan = RecoveryPlan(
                risk=Severity.WARNING,
                proposed_actions=[
                    "Preserve collected evidence",
                    "Review the diagnostic recommendations before making changes",
                ],
                rollback=["No changes were made by this plan"],
                execute_supported=False,
                notes=[f"{self.name} execute mode is not implemented; operator approval is still required."],
            )
        return incidents

    def execute(self, context: InvestigationContext) -> list[Incident]:
        incidents = self.plan(context)
        for incident in incidents:
            if incident.plan:
                incident.plan.notes.append("Execution is not implemented for this module.")
        return incidents
