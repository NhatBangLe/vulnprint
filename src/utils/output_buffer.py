from typing import Optional


class OutputBuffer:
    """
    Helper to aggregate and display prints, saving the output as a Markdown-formatted code block when requested.
    """

    def __init__(self, export_path: Optional[str] = None):
        self.export_path = export_path
        self.buffer = []

    def write(self, text: str = "") -> None:
        try:
            print(text)
        except UnicodeEncodeError:
            safe_text = text.replace("█", "#")
            try:
                print(safe_text)
            except Exception:
                import sys

                enc = sys.stdout.encoding or "ascii"
                try:
                    print(text.encode(enc, errors="replace").decode(enc))
                except Exception:
                    pass
        self.buffer.append(text)

    def save(self) -> None:
        if not self.export_path:
            return
        try:
            import os

            # Ensure directories exist
            dir_name = os.path.dirname(self.export_path)
            if dir_name and not os.path.exists(dir_name):
                os.makedirs(dir_name, exist_ok=True)

            with open(self.export_path, "w", encoding="utf-8") as f:
                f.write("# Vulnprint Export Report\n\n")
                f.write("```text\n")
                f.write("\n".join(self.buffer))
                f.write("\n```\n")
        except Exception as e:
            print(f"Error exporting report: {e}")
