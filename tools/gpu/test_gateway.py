import os
import subprocess
import tempfile
import time
import unittest
import uuid
from pathlib import Path

from aws_host import NGINX, gateway

BACKEND = "python:3.12-alpine"
# ECR Public caps anonymous pulls per source IP, and hosted runners share their
# IPs, so it can refuse with "toomanyrequests: Data limit exceeded". Its
# docker/library images mirror Docker Hub's official ones, so the pinned digest
# pulls byte for byte from Docker Hub too.
NGINX_MIRROR = NGINX.replace("public.ecr.aws/docker/library/", "docker.io/library/", 1)


@unittest.skipUnless(os.environ.get("GPU_GATEWAY_TEST") == "1", "requires Docker")
class GatewayTest(unittest.TestCase):
    def test_auth_and_indexer_proxy(self):
        name = "gpu-gateway-test-" + uuid.uuid4().hex[:12]
        backend = """
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlsplit
import hmac
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlsplit(self.path)
        key = (
            self.headers.get('X-API-Key')
            or self.headers.get('Authorization', '').removeprefix('Bearer ')
            or parse_qs(url.query).get('api-key', [''])[0]
        )
        code = 204 if url.path == '/auth' else 200
        public = url.path in ('/proving-keys', '/v1/zolana/proving-keys')
        if self.server.server_port == 3003 and not public and not hmac.compare_digest(key, 'secret'):
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
def request(path, key=None, data=None, method=None, query=False):
    headers = {'X-API-Key': key} if key and not query else {}
    if key and query:
        path += '?api-key=' + key
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
for path in ('/ready', '/indexer', '/indexer/readiness', '/prove/indexed', '/v1/zolana/prove/indexed', '/proving-keys/extra'):
    assert request(path)[0] == 401, path
    assert request(path, 'wrong')[0] == 401, path
    code, _, cors = request(path, 'secret')
    assert code == 200 and cors == ['*'], (path, code, cors)
    assert request(path, 'wrong', query=True)[0] == 401, path
    assert request(path, 'secret', query=True)[0] == 200, path
for path in ('/proving-keys', '/v1/zolana/proving-keys'):
    for key in (None, 'wrong', 'secret'):
        assert request(path, key)[0] == 200, path
assert request('/_authorize', 'secret')[0] == 404
assert request('/indexer', 'secret', b'{"jsonrpc":"2.0"}')[1] == b'{"jsonrpc":"2.0"}'
assert request('/indexer', method='OPTIONS')[0] == 204
"""

        def docker(*args):
            result = subprocess.run(
                ["docker", *args],
                text=True,
                capture_output=True,
                timeout=120,
            )
            if result.returncode != 0:
                self.fail(
                    f"docker {' '.join(args)} exited {result.returncode}: "
                    f"{result.stderr.strip()}"
                )
            return result

        # Pulled before the test starts, so a registry refusing an anonymous
        # pull is not mistaken for a gateway failure. Returns the first
        # reference that pulls.
        def pull(*images):
            errors = []
            for image in images:
                result = subprocess.run(
                    ["docker", "pull", "--quiet", image],
                    text=True,
                    capture_output=True,
                    timeout=120,
                )
                if result.returncode == 0:
                    return image
                errors.append(f"docker pull {image}: {result.stderr.strip()}")
            self.fail("\n".join(errors))

        # nginx joins the backend's network namespace, which exists only
        # while the backend runs.
        def wait_running(container):
            for _ in range(20):
                state = docker("inspect", "--format", "{{.State.Running}}", container)
                if state.stdout.strip() == "true":
                    return
                time.sleep(0.25)
            logs = subprocess.run(
                ["docker", "logs", container], text=True, capture_output=True, timeout=30
            )
            self.fail(f"{container} is not running: {logs.stdout}{logs.stderr}")

        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "nginx.conf"
            config.write_text(gateway(True))
            config.chmod(0o644)
            pull(BACKEND)
            nginx = pull(NGINX, NGINX_MIRROR)
            try:
                docker(
                    "run",
                    "-d",
                    "--name",
                    name,
                    BACKEND,
                    "python",
                    "-c",
                    backend,
                )
                wait_running(name)
                docker(
                    "run",
                    "-d",
                    "--name",
                    name + "-nginx",
                    "--network",
                    "container:" + name,
                    "-v",
                    f"{config}:/etc/nginx/nginx.conf:ro",
                    nginx,
                )
                docker("exec", name, "python", "-c", checks)
                logs = docker("logs", name + "-nginx")
                self.assertNotIn("api-key", logs.stdout + logs.stderr)
            finally:
                subprocess.run(
                    ["docker", "rm", "-f", name + "-nginx", name],
                    check=False,
                    capture_output=True,
                    timeout=30,
                )


if __name__ == "__main__":
    unittest.main()
