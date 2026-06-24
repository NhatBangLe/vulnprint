import sys

def safe_print(text: str) -> None:
    try:
        print(text)
    except UnicodeEncodeError:
        enc = sys.stdout.encoding or 'utf-8'
        try:
            print(text.encode(enc, errors='replace').decode(enc))
        except Exception:
            print(text.encode('ascii', errors='replace').decode('ascii'))
