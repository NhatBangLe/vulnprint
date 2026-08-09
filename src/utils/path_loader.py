import os
import json
from typing import List


def load_msf_paths_from_file(file_path: str) -> List[str]:
    """
    Loads Metasploit module paths from a file.
    Supports:
    - JSONL (JSON Lines): each line is a JSON object like {"msf_path": "..."} or a JSON string.
    - JSON Array: a JSON file containing a list of strings or dict objects.
    - Plain Text: lines of raw path strings.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Input file not found: '{file_path}'")

    paths: List[str] = []

    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read().strip()

    if not content:
        return []

    # 1. Attempt to parse entire content as JSON array / object
    try:
        data = json.loads(content)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str) and item.strip():
                    paths.append(item.strip())
                elif isinstance(item, dict):
                    p = item.get("msf_path") or item.get("path") or item.get("module_path")
                    if p and str(p).strip():
                        paths.append(str(p).strip())
            if paths:
                return paths
        elif isinstance(data, dict):
            p = data.get("msf_path") or data.get("path") or data.get("module_path")
            if p and str(p).strip():
                return [str(p).strip()]
    except Exception:
        pass

    # 2. Process line-by-line for JSONL or plain text
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            line_obj = json.loads(line)
            if isinstance(line_obj, str) and line_obj.strip():
                paths.append(line_obj.strip())
            elif isinstance(line_obj, dict):
                p = line_obj.get("msf_path") or line_obj.get("path") or line_obj.get("module_path")
                if p and str(p).strip():
                    paths.append(str(p).strip())
        except Exception:
            # Fallback for raw text lines
            paths.append(line)

    return paths
