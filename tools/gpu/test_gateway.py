import os
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path

from aws_host import NGINX, gateway


@unittest.skipUnless(os.environ.get("GPU_GATEWAY_TEST") == "1", "requires Docker")
class GatewayTest(unittest.TestCase):
    def test_auth_and_indexer_proxy(self):
        name = "gpu-gateway-test-" + uuid.uuid4().hex[:12]
        backend = """
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import hmac
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        key = self.headers.get('X-API-Key') or self.headers.get('Authorization', '').removeprefix('Bearer ')
        code = 204 if self.path == '/auth' else 200
        if self.server.server_port == 3003 and not hmac.compare_digest(key, 'secret'):
            code = 401
        self.send_response(code)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)
for port in (3003, 8784):
    Thread(target=ThreadingHTTPServer(('127.0.0.1', port), Handler).serve_forever, daemon=True).start()
__import__('time').sleep(120)
"""
        checks = """
import time, urllib.request, urllib.error
def request(path, key=None, data=None, method=None):
    headers = {'X-API-Key': key} if key else {}
    try:
        with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:3001' + path, data=data, headers=headers, method=method), timeout=5) as response:
            return response.status, response.read(), response.headers.get_all('Access-Control-Allow-Origin')
    except urllib.error.HTTPError as error:
        return error.code, b'', []
for attempt in range(20):
    try:
        request('/ready')
        break
    except urllib.error.URLError:
        time.sleep(0.25)
for path in ('/ready', '/indexer', '/indexer/readiness'):
    assert request(path)[0] == 401, path
    assert request(path, 'wrong')[0] == 401, path
    code, _, cors = request(path, 'secret')
    assert code == 200 and cors == ['*'], (path, code, cors)
assert request('/_authorize', 'secret')[0] == 404
assert request('/indexer', 'secret', b'{"jsonrpc":"2.0"}')[1] == b'{"jsonrpc":"2.0"}'
assert request('/indexer', method='OPTIONS')[0] == 204
"""

        def docker(*args):
            return subprocess.run(
                ["docker", *args],
                check=True,
                text=True,
                capture_output=True,
                timeout=120,
            )

        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "nginx.conf"
            config.write_text(gateway(True))
            config.chmod(0o644)
            try:
                docker(
                    "run",
                    "-d",
                    "--name",
                    name,
                    "python:3.12-alpine",
                    "python",
                    "-c",
                    backend,
                )
                docker(
                    "run",
                    "-d",
                    "--name",
                    name + "-nginx",
                    "--network",
                    "container:" + name,
                    "-v",
                    f"{config}:/etc/nginx/nginx.conf:ro",
                    NGINX,
                )
                docker("exec", name, "python", "-c", checks)
            finally:
                subprocess.run(
                    ["docker", "rm", "-f", name + "-nginx", name],
                    check=False,
                    capture_output=True,
                    timeout=30,
                )


if __name__ == "__main__":
    unittest.main()
