import os
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path

import aws_nitro_host as host

from aws_host import NGINX, gateway
from test_gateway import BACKEND, NGINX_MIRROR

TOOLS = Path(__file__).resolve().parents[1]
INGRESS = [host.ingress_port(index) for index in range(2)]
SERVERS = f"""
import json, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sys.path[:0] = ['/tools/nitro', '/tools/gpu']
import aws_nitro_host
class Echo(BaseHTTPRequestHandler):
    def answer(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        echoed = json.dumps({{'method': self.command, 'path': self.path, 'headers': dict(self.headers), 'body': body.hex(), 'port': self.server.server_port}}).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(echoed)))
        self.end_headers()
        self.wfile.write(echoed)
    do_GET = do_POST = answer
for port in {INGRESS}:
    threading.Thread(target=ThreadingHTTPServer(('127.0.0.1', port), Echo).serve_forever, daemon=True).start()
aws_nitro_host.serve_authorizer('secret', {host.AUTHORIZER_PORT})
"""
CHECKS = f"""
import json, time, urllib.request, urllib.error
base = 'http://127.0.0.1:{host.GATEWAY_PORT}'
def request(path, headers=None, data=None, method=None):
    try:
        with urllib.request.urlopen(urllib.request.Request(base + path, data=data, headers=headers or {{}}, method=method), timeout=5) as response:
            return response.status, response.read(), response.headers
    except urllib.error.HTTPError as error:
        return error.code, b'', error.headers
for _ in range(80):
    try:
        if request('/proving-keys')[0] == 200:
            break
    except OSError:
        pass
    time.sleep(0.25)
for path in ('/ready', '/prove/transfer_confidential_2_3', '/tee/v1/attestation?nonce=00'):
    assert request(path)[0] == 401, path
    assert request(path, {{'X-API-Key': 'wrong'}})[0] == 401, path
    assert request(path, {{'X-API-Key': 'secret'}})[0] == 200, path
    assert request(path, {{'Authorization': 'Bearer secret'}})[0] == 200, path
    sep = '&' if '?' in path else '?'
    assert request(path + sep + 'api-key=secret')[0] == 200, path
assert request('/proving-keys')[0] == 200
body = bytes(range(256)) * 4
headers = {{'X-API-Key': 'secret', 'Content-Type': 'application/octet-stream', 'Zolana-Tee': 'v1', 'Zolana-Tee-Enc': 'ab' * 32}}
status, echoed, _ = request('/v1/zolana/prove/merge_8_1?a=1&api-key=secret&b=2', headers, body, 'POST')
echoed = json.loads(echoed)
assert status == 200 and bytes.fromhex(echoed['body']) == body, echoed
assert echoed['path'] == '/v1/zolana/prove/merge_8_1?a=1&api-key=secret&b=2', echoed['path']
assert echoed['headers']['Zolana-Tee'] == 'v1' and echoed['headers']['Zolana-Tee-Enc'] == 'ab' * 32
assert echoed['headers']['Content-Type'] == 'application/octet-stream'
status, echoed, _ = request('/ready', {{'X-API-Key': 'secret', 'Zolana-Tee': 'v1', 'Zolana-Tee-Ciphertext': 'cd' * 40}})
assert json.loads(echoed)['headers']['Zolana-Tee-Ciphertext'] == 'cd' * 40
status, _, headers = request('/ready', {{'Origin': 'https://app.example', 'Access-Control-Request-Headers': 'zolana-tee'}}, method='OPTIONS')
assert status == 204 and headers['Access-Control-Allow-Origin'] == '*', status
assert 'Zolana-Tee-Ciphertext' in headers['Access-Control-Allow-Headers']
assert 'Zolana-Tee' in request('/ready', {{'X-API-Key': 'secret'}})[2]['Access-Control-Expose-Headers']
ports = [json.loads(request('/ready', {{'X-API-Key': 'secret'}})[1])['port'] for _ in range(4)]
assert sorted(ports) == sorted({INGRESS} * 2) and ports[0] != ports[1], ports
"""


@unittest.skipUnless(os.environ.get("NITRO_GATEWAY_TEST") == "1", "requires Docker")
class GatewayTest(unittest.TestCase):
    def docker(self, *args):
        completed = subprocess.run(
            ["docker", *args], text=True, capture_output=True, timeout=180
        )
        if completed.returncode:
            self.fail(
                f"docker {args[0]} exited {completed.returncode}: {completed.stderr.strip()}"
            )
        return completed

    def pull(self, *images):
        for image in images:
            if (
                subprocess.run(
                    ["docker", "pull", "--quiet", image],
                    capture_output=True,
                    timeout=180,
                ).returncode
                == 0
            ):
                return image
        self.fail(f"Could not pull {images[0]}")

    def test_gateway_enforces_the_key_and_passes_tee_requests(self):
        name = "nitro-gateway-test-" + uuid.uuid4().hex[:12]
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "nginx.conf"
            config.write_text(
                gateway(
                    False,
                    authorizer=f"http://127.0.0.1:{host.AUTHORIZER_PORT}/auth",
                    upstreams=[f"127.0.0.1:{port}" for port in INGRESS],
                )
            )
            config.chmod(0o644)
            nginx = self.pull(NGINX, NGINX_MIRROR)
            self.pull(BACKEND)
            try:
                self.docker(
                    "run",
                    "-d",
                    "--name",
                    name,
                    "-v",
                    f"{TOOLS}:/tools:ro",
                    BACKEND,
                    "python",
                    "-c",
                    SERVERS,
                )
                self.docker(
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
                self.docker("exec", name, "python", "-c", CHECKS)
                logs = self.docker("logs", name + "-nginx")
                self.assertNotIn("secret", logs.stdout + logs.stderr)
            finally:
                subprocess.run(
                    ["docker", "rm", "-f", name + "-nginx", name],
                    capture_output=True,
                    timeout=60,
                )


if __name__ == "__main__":
    unittest.main()
