// Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
// One proof or verification per runtime, including fresh ECDSA child workers.
let started = false;

self.onmessage = async ({ data }) => {
  if (started) return;
  started = true;
  let preparation;
  let result;
  let transfer = [];
  const startedAt = performance.now();

  try {
    const { role, config, proof } = data;
    if (role !== "prover" && role !== "verifier") {
      throw new Error("Unknown proof role");
    }
    if (config.program !== "modules/payroll_verification.wasm") {
      throw new Error("Unknown payment circuit");
    }
    const assetBase = new URL("./", self.location.href);
    importScripts(new URL("ecdsa_precompute.js", assetBase).href);
    // Public template decompression and fixed-table workers overlap backend
    // and program loading. No private values are supplied until callMain.
    preparation = LigeroEcdsaR1cs.precompute({
      assetBase,
      prover: role === "prover",
      parallel: true,
    });

    let resolveReady;
    let rejectReady;
    let rejectAbort;
    const ready = new Promise((resolve, reject) => {
      resolveReady = resolve;
      rejectReady = reject;
    });
    const aborted = new Promise((_, reject) => { rejectAbort = reject; });
    aborted.catch(() => {});
    let finalResult = null;
    const scan = (target, content) => {
      // The backend prints arguments. Keep these out of browser logs and
      // saved benchmark results, even when a fixture contains private data.
      for (const line of content.split(/\r?\n/)) {
        if (!/^args\s*:/i.test(line.trim())) {
          self.postMessage({ target, content: line });
        }
      }
      const verb = role === "prover" ? "prove" : "verify";
      const match = new RegExp(`final\\s+${verb}\\s+result:\\s+(\\w+)`, "i").exec(content);
      if (match) finalResult = match[1].toLowerCase() === "true";
    };

    globalThis.Module = {
      noInitialRun: true,
      locateFile: file => new URL(file, assetBase).href,
      print: content => scan("stdout", String(content)),
      printErr: content => scan("stderr", String(content)),
      setStatus: value => self.postMessage({ target: "status", value }),
      onRuntimeInitialized: resolveReady,
      onAbort: reason => {
        const error = new Error(`Payment runtime aborted: ${reason}`);
        rejectReady(error);
        rejectAbort(error);
      },
    };
    const programDownload = fetch(new URL("payroll_verification.wasm", assetBase))
      .then(response => {
        if (!response.ok) throw new Error("Cannot fetch payment circuit");
        return response.arrayBuffer();
      });
    const loaded = Promise.all([ready, programDownload]);
    loaded.catch(() => {});
    importScripts(new URL(`webgpu_${role}.js`, assetBase).href);
    const [, program] = await Promise.race([loaded, aborted]);
    self.postMessage({ target: "status", value: "Preparing public ECDSA template and tables" });
    await Promise.race([preparation.prepare(Module), aborted]);
    Module.FS.mkdirTree("/modules");
    Module.FS.writeFile("/modules/payroll_verification.wasm", new Uint8Array(program));
    if (role === "verifier") {
      if (!(proof instanceof Uint8Array) || proof.length === 0) {
        throw new Error("Missing proof for verification");
      }
      Module.FS.writeFile("/proof_data.gz", proof);
    }

    const preparedAt = performance.now();
    self.postMessage({ target: "status", value: role === "prover" ? "Proving" : "Verifying" });
    let status = Module.callMain([JSON.stringify(config)]);
    if (typeof Asyncify !== "undefined" && Asyncify.currData) {
      status = await Promise.race([Asyncify.whenDone(), aborted]);
    } else if (status && typeof status.then === "function") {
      status = await Promise.race([status, aborted]);
    }
    const finishedAt = performance.now();
    if (status !== 0 || finalResult !== true) {
      throw new Error(`Payment ${role} failed (exit ${status})`);
    }
    result = {
      target: "complete",
      preparationMs: preparedAt - startedAt,
      mainMs: finishedAt - preparedAt,
    };
    if (role === "prover") {
      const bytes = Module.FS.readFile("/proof_data.gz");
      if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
        throw new Error("Empty payment proof");
      }
      result.proof = bytes;
      transfer = [bytes.buffer];
    }
  } catch (error) {
    result = { target: "error", message: error instanceof Error ? error.message : String(error) };
  } finally {
    // Dispose children before completion is posted: the controller terminates
    // this worker immediately after receiving the result.
    preparation?.dispose();
  }

  result.workerMs = performance.now() - startedAt;
  self.postMessage(result, transfer);
  self.close();
};
