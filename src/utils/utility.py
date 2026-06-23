import sys

def safe_print(text: str) -> None:
    try:
        print(text)
    except UnicodeEncodeError:
        try:
            sys.stdout.buffer.write(text.encode(sys.stdout.encoding or 'utf-8', errors='replace'))
            print()
        except Exception:
            print(text.encode('ascii', errors='replace').decode('ascii'))
