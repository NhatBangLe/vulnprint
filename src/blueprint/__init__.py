try:
    from src.blueprint.base import BlueprintService
    from src.blueprint.generator import MarkdownBlueprintService
except ImportError:
    from .base import BlueprintService
    from .generator import MarkdownBlueprintService
