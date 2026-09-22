import json
import os
from urllib.parse import unquote, urlsplit


def database_identity(value):
    url = urlsplit(value)
    if url.scheme != "postgres" or url.hostname not in ("127.0.0.1", "::1"):
        raise ValueError("Use a postgres URL with a loopback IP address")
    # 1. Libpq query options can override the URL host.
    if url.query or url.fragment or any(ord(char) < 32 for char in value):
        raise ValueError("Database URL options and control characters are not accepted")
    if not url.username or not url.path.strip("/"):
        raise ValueError("Set an explicit database user and name")
    return json.dumps([url.hostname, url.port or 5432, unquote(url.path[1:]), unquote(url.username)])


if __name__ == "__main__":
    try:
        print(database_identity(os.environ["DATABASE_URL"]))
    except (KeyError, ValueError):
        raise SystemExit("Invalid local database configuration") from None
