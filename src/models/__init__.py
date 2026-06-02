try:
    from src.models.models import (
        CLIArguments,
        ExploitDetails,
        MetasploitModuleDetails,
        VulnerabilityRecord,
    )
except ImportError:
    from .models import (
        CLIArguments,
        ExploitDetails,
        MetasploitModuleDetails,
        VulnerabilityRecord,
    )
