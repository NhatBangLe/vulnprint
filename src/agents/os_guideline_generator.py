import logging
from typing import Optional, TYPE_CHECKING
from models import OSGuideline, GuidelineStatus
from utils import (
    format_validation_error_details,
    AgentExecutionError,
    AgentPreconditionError,
    AgentSchemaValidationError,
    AgentStepTracker,
    AgentExecutionTrace,
    AgentResult,
)
from pydantic import ValidationError

if TYPE_CHECKING:
    from services.msf_module import MSFModuleService
    from services.software import SoftwareService


EXPECTED_OS_GUIDELINE_STEPS = [
    "Entity Verification & Preconditions",
    "OS Specification Parsing",
    "OS Guideline Construction & Status Assignment",
]


class OSGuidelineGeneratorAgent:
    def __init__(
        self,
        msf_service: "MSFModuleService",
        soft_service: "SoftwareService",
    ):
        self.msf_service = msf_service
        self.soft_service = soft_service
        self._logger = logging.getLogger(self.__class__.__name__)
        self.last_trace: Optional[AgentExecutionTrace] = None

    def generate_with_trace(
        self,
        msf_path: str,
        raise_on_error: bool = False,
    ) -> AgentResult[OSGuideline]:
        """
        Executes OS guideline generation with complete step-by-step traceability.
        Returns an AgentResult containing data, full execution trace, and any error.
        """
        tracker = AgentStepTracker(
            agent_name=self.__class__.__name__,
            target_identifier=msf_path,
            expected_steps=EXPECTED_OS_GUIDELINE_STEPS,
        )
        self.last_trace = tracker.trace

        # Step 1: Entity Verification & Preconditions
        current_step = EXPECTED_OS_GUIDELINE_STEPS[0]
        tracker.start_step(current_step, metadata={"msf_path": msf_path})

        msf_module = self.msf_service.get_module_by_path(msf_path)
        if not msf_module:
            err_msg = f"Metasploit module '{msf_path}' not found in database."
            hint = "Ingest the Metasploit module details into the database first."
            tracker.fail_step(
                name=current_step,
                error=err_msg,
                error_category="AgentPreconditionError",
                diagnostic_hint=hint,
            )
            self._logger.error(tracker.trace.format_visual_box())
            error = AgentPreconditionError(
                message=err_msg,
                agent_name=self.__class__.__name__,
                step_name=current_step,
                step_index=1,
                diagnostic_hint=hint,
                trace=tracker.trace,
            )
            if raise_on_error:
                raise error
            return AgentResult(data=None, trace=tracker.trace, error=error)

        software = self.soft_service.get_software_by_path(msf_path)
        if not software:
            err_msg = f"Software record not found in database for path: '{msf_path}'."
            hint = "Run vulnerability target extraction to identify the software and target OS before generating OS guidelines."
            tracker.fail_step(
                name=current_step,
                error=err_msg,
                error_category="AgentPreconditionError",
                diagnostic_hint=hint,
            )
            self._logger.error(tracker.trace.format_visual_box())
            error = AgentPreconditionError(
                message=err_msg,
                agent_name=self.__class__.__name__,
                step_name=current_step,
                step_index=1,
                diagnostic_hint=hint,
                trace=tracker.trace,
            )
            if raise_on_error:
                raise error
            return AgentResult(data=None, trace=tracker.trace, error=error)

        tracker.complete_step(
            current_step,
            metadata={
                "platform": software.platform,
                "distribution": software.distribution,
                "version": software.version,
                "architecture": software.architecture,
            },
        )

        # Step 2: OS Specification Parsing
        current_step = EXPECTED_OS_GUIDELINE_STEPS[1]
        tracker.start_step(current_step)
        parts = []
        if software.distribution:
            parts.append(software.distribution)
        else:
            parts.append(software.platform)
        if software.version:
            parts.append(software.version)
        if software.architecture:
            parts.append(f"({software.architecture})")
        os_name = " ".join(parts)
        tracker.complete_step(current_step, metadata={"resolved_os_name": os_name})

        # Step 3: OS Guideline Construction & Status Assignment
        current_step = EXPECTED_OS_GUIDELINE_STEPS[2]
        tracker.start_step(current_step)
        try:
            os_guideline = OSGuideline(
                guideline=f"Install the base operating system: {os_name}.",
                platform=software.platform,
                distribution=software.distribution,
                version=software.version,
                architecture=software.architecture,
                status=GuidelineStatus.VERIFIED,
            )
            tracker.complete_step(
                current_step,
                metadata={"status": os_guideline.status.value},
            )
            tracker.finish(success=True)
            return AgentResult(data=os_guideline, trace=tracker.trace, error=None)
        except ValidationError as e:
            details = format_validation_error_details(e)
            tracker.fail_step(
                name=current_step,
                error=details,
                error_category="AgentSchemaValidationError",
                diagnostic_hint="OSGuideline domain model constraints were violated.",
            )
            self._logger.error(tracker.trace.format_visual_box())
            error = AgentSchemaValidationError(
                message=details,
                agent_name=self.__class__.__name__,
                step_name=current_step,
                step_index=3,
                trace=tracker.trace,
            )
            if raise_on_error:
                raise error
            return AgentResult(data=None, trace=tracker.trace, error=error)
        except Exception as e:
            err_msg = f"Error during OS guideline generation: {e}"
            tracker.fail_step(
                name=current_step,
                error=e,
                error_category="AgentExecutionError",
            )
            self._logger.error(tracker.trace.format_visual_box())
            error = AgentExecutionError(
                message=err_msg,
                agent_name=self.__class__.__name__,
                step_name=current_step,
                step_index=3,
                trace=tracker.trace,
            )
            if raise_on_error:
                raise error
            return AgentResult(data=None, trace=tracker.trace, error=error)

    def generate(
        self,
        msf_path: str,
        raise_on_error: bool = False,
    ) -> Optional[OSGuideline]:
        """
        Generates base OS setup instructions.
        Maintains backward compatibility while preserving full step traceability in self.last_trace.
        """
        result = self.generate_with_trace(
            msf_path=msf_path,
            raise_on_error=raise_on_error,
        )
        return result.data
