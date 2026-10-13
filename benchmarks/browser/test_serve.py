#!/usr/bin/env python3
# Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
"""HTTP route and result-saving tests; no browser or GPU is used."""
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
from types import SimpleNamespace
import unittest

from serve import handler_for, make_state


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        root = Path(self.temporary.name)
        web, witness, fixtures = (root / name for name in ("web", "witness", "fixtures"))
        for directory in (web, witness, fixtures):
            directory.mkdir()
        for role in ("prover", "verifier"):
            for extension in ("js", "wasm", "data"):
                (web / f"webgpu_{role}.{extension}").write_bytes(b"test")
        for name in ("ecdsa_witness.js", "ecdsa_witness.wasm"):
            (witness / name).write_bytes(b"test")
        for name in ("test_send", "test_send_tron"):
            (fixtures / f"{name}.json").write_text("{}")
        program, template = root / "payment.wasm", root / "template.gz"
        program.write_bytes(b"test")
        template.write_bytes(b"test")
        self.state = make_state(SimpleNamespace(
            baseline_assets=None, baseline_commitment_cache_mb=None,
            candidate_web=web, witness_build=witness,
            program=program, template=template, fixtures=fixtures,
            output=root / "results", commitment_cache_mb=768))
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(self.state))
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temporary.cleanup()

    def request(self, path, method="GET", body=None, headers=None):
        connection = HTTPConnection(*self.server.server_address)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        status, data = response.status, response.read()
        connection.close()
        return status, data

    def test_only_allowlisted_files_are_served(self):
        for path in ("/", "/candidate/webgpu_prover.wasm", "/candidate-cached/ecdsa_witness.js"):
            self.assertEqual(self.request(path)[0], 200)
        for path in ("/../../etc/passwd", "/candidate/../serve.py", "/candidate/%2e%2e/serve.py",
                     "/fixtures/unknown.json", "/baseline/webgpu_prover.js"):
            self.assertEqual(self.request(path)[0], 404)
        self.assertEqual(self.request("/config", headers={"Host": "untrusted.example"})[0], 403)

    def test_result_requires_token_and_is_saved_only_to_output(self):
        report = dict(schemaVersion=1, sessionId=self.state["manifest"]["sessionId"], records=[])
        encoded = json.dumps(report)
        headers = {"Content-Type": "application/json"}
        self.assertEqual(self.request("/results", "POST", encoded, headers)[0], 403)
        headers["X-Benchmark-Token"] = self.state["token"]
        self.assertEqual(self.request("/results", "POST", encoded, headers)[0], 200)
        self.assertEqual(json.loads((self.state["output"] / "results.json").read_text()), report)
        self.assertEqual(json.loads(self.request("/results")[1]), report)
        headers["Origin"] = "https://untrusted.example"
        self.assertEqual(self.request("/results", "POST", encoded, headers)[0], 403)

    def test_invalid_result_does_not_replace_saved_result(self):
        headers = {"Content-Type": "application/json", "X-Benchmark-Token": self.state["token"]}
        bad = dict(schemaVersion=1, sessionId="different-session", records=[])
        self.assertEqual(self.request("/results", "POST", json.dumps(bad), headers)[0], 400)
        self.assertFalse((self.state["output"] / "results.json").exists())


if __name__ == "__main__":
    unittest.main()
