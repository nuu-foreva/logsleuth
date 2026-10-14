"""Allow ``python -m logsleuth``."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
