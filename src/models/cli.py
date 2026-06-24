from typing import Optional
from pydantic import BaseModel


class CLIArguments(BaseModel):
    search: Optional[str] = None
    analytics: bool = False
    summary: bool = False
    list_software: bool = False
    search_db: Optional[str] = None
    platform: Optional[str] = None
    rank: Optional[str] = None
    export: Optional[str] = None
    limit: Optional[int] = None
    review: bool = False
    export_guide: Optional[str] = None
    export_guideline_by_os: Optional[str] = None
    min_date: Optional[str] = None
    max_date: Optional[str] = None
    sort_date: Optional[str] = None
