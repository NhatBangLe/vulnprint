try:
    from src.metasploit.base import MetasploitService
    from src.metasploit.client import MetasploitRPCService
except ImportError:
    from .base import MetasploitService
    from .client import MetasploitRPCService
