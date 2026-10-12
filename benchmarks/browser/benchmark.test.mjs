// Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
import assert from "node:assert/strict";
import test from "node:test";
import { maskPrivateInputs, median, runWorker, sanitizedLines, summarize } from "./benchmark.mjs";

const fixture = {
  args: [{ hex: "ab00" }, { i64: 42 }, { hex: "1234" }, { str: "é" }],
  "private-indices": [1, 2, 4],
  program: "modules/payroll_verification.wasm",
};

test("masking preserves public arguments, metadata, byte widths, and original inputs", () => {
  const before = structuredClone(fixture);
  const masked = maskPrivateInputs(fixture);
  assert.deepEqual(masked.args, [{ hex: "0000" }, { i64: 0 }, { hex: "1234" }, { str: "00" }]);
  assert.deepEqual(masked["private-indices"], fixture["private-indices"]);
  assert.deepEqual(fixture, before);
});

test("unsupported or malformed private arguments fail closed", () => {
  for (const change of [
    { "private-indices": [0] },
    { "private-indices": [5] },
    { "private-indices": [1, 1] },
    { args: [{ unknown: "secret" }], "private-indices": [1] },
    { args: [{ hex: "abc" }], "private-indices": [1] },
  ]) assert.throws(() => maskPrivateInputs({ ...fixture, ...change }));
});

test("medians exclude warmups", () => {
  const records = [-1, 0, 1, 2].map(run => ({ version: "candidate", fixture: "test_send", run,
    prove: { preparationMs: run < 0 ? 999 : 1, mainMs: run < 0 ? 999 : run + 2, wallMs: 8 },
    verify: { preparationMs: 1, mainMs: 2, wallMs: 3 }, proofBytes: 100 }));
  assert.equal(summarize(records)[0].prove.mainMs, 3);
  assert.equal(summarize(records)[0].runs, 3);
  assert.equal(median([4, 1, 3, 2]), 2.5);
});

test("backend argument logs are omitted, including multiline output", () => {
  assert.deepEqual(sanitizedLines("Start\nargs: {secret}\n\u001b[31mFinal prove result: true\u001b[0m"),
    ["Start", "Final prove result: true"]);
});

class FakeWorker {
  static instances = [];
  constructor(url) {
    this.url = String(url);
    this.terminations = 0;
    FakeWorker.instances.push(this);
  }
  postMessage(message, transfer) { this.message = message; this.transfer = transfer; }
  terminate() { this.terminations += 1; }
  emit(data) { this.onmessage({ data }); }
}

function start(role = "prover", extras = {}) {
  const promise = runWorker({ assetBase: "http://127.0.0.1:8789/candidate/", role,
    config: structuredClone(fixture), WorkerClass: FakeWorker, ...extras });
  return { promise, worker: FakeWorker.instances.at(-1) };
}

const complete = () => ({ target: "complete", preparationMs: 2, mainMs: 3, workerMs: 6,
  proof: new Uint8Array([1, 2, 3]) });

test("each operation gets a fresh worker and completion settles once", async () => {
  const first = start();
  first.worker.emit(complete());
  first.worker.emit({ target: "error", message: "late failure" });
  const proof = await first.promise;
  assert.equal(proof.proof.length, 3);
  assert.equal(first.worker.terminations, 1);
  const second = start("verifier", { config: maskPrivateInputs(fixture), proof: proof.proof });
  assert.notEqual(first.worker, second.worker);
  assert.equal(second.worker.message.config.args[0].hex, "0000");
  assert.deepEqual(second.worker.transfer, [proof.proof.buffer]);
  second.worker.emit({ target: "complete", preparationMs: 1, mainMs: 2, workerMs: 3 });
  await second.promise;
  assert.equal(second.worker.terminations, 1);
});

test("empty proofs, errors, crashes, and timeouts reject without reusing a proof", async () => {
  for (const fail of [
    worker => worker.emit({ ...complete(), proof: new Uint8Array() }),
    worker => worker.emit({ target: "error", message: "backend failure" }),
    worker => worker.onerror({ message: "worker crash" }),
  ]) {
    const attempt = start();
    fail(attempt.worker);
    attempt.worker.emit(complete());
    await assert.rejects(attempt.promise);
    assert.equal(attempt.worker.terminations, 1);
  }
  const timed = start("prover", { timeoutMs: 2 });
  await assert.rejects(timed.promise, /timed out/);
  assert.equal(timed.worker.terminations, 1);
});

test("postMessage failures clean up the new worker", async () => {
  class ThrowingWorker extends FakeWorker {
    postMessage() { throw new Error("clone failed"); }
  }
  const attempt = start("prover", { WorkerClass: ThrowingWorker });
  await assert.rejects(attempt.promise, /clone failed/);
  assert.equal(attempt.worker.terminations, 1);
});
