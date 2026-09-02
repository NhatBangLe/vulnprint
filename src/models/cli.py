from typing import Optional
from pydantic import BaseModel


class CLIArguments(BaseModel):
    command: Optional[str] = None
    subcommand: Optional[str] = None
    query: Optional[str] = None
    pattern: Optional[str] = None
    target: Optional[str] = None
    os_id: Optional[int] = None
    platform: Optional[str] = None
    rank: Optional[str] = None
    output: Optional[str] = None
    limit: Optional[int] = None
    min_date: Optional[str] = None
    max_date: Optional[str] = None
    sort_date: Optional[str] = None
    msf_path: Optional[str] = None
    no_guideline: bool = False
    input_file: Optional[str] = None
    agent: Optional[str] = None
    error_category: Optional[str] = None
    verbose_trace: bool = False
    trace_path: Optional[str] = None
    status: Optional[str] = None
