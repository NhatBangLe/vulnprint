try:
    from src.ai_parser.base import VulnerabilityMetadataExtractor
    from src.ai_parser.parser import LLMVulnerabilityMetadataExtractor
except ImportError:
    from .base import VulnerabilityMetadataExtractor
    from .parser import LLMVulnerabilityMetadataExtractor
