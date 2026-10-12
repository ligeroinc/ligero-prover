// Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.

export function maskPrivateInputs(config) {
  const masked = structuredClone(config);
  if (!Array.isArray(masked.args) || !Array.isArray(masked["private-indices"])) {
    throw new Error("Fixture must declare arguments and private-indices");
  }
  const seen = new Set();
  for (const index of masked["private-indices"]) {
    if (!Number.isInteger(index) || index < 1 || index > masked.args.length || seen.has(index)) {
      throw new Error("Invalid private argument index");
    }
    seen.add(index);
    const argument = masked.args[index - 1];
    if (!argument || typeof argument !== "object" || Object.keys(argument).length !== 1) {
      throw new Error("Invalid private argument");
    }
    if (typeof argument.hex === "string" && /^(?:[0-9a-f]{2})*$/i.test(argument.hex)) {
      argument.hex = "0".repeat(argument.hex.length);
    } else if (Object.hasOwn(argument, "i64") &&
               (typeof argument.i64 === "number" || typeof argument.i64 === "string")) {
      argument.i64 = typeof argument.i64 === "string" ? "0" : 0;
    } else if (typeof argument.str === "string") {
      argument.str = "0".repeat(new TextEncoder().encode(argument.str).length);
    } else {
      throw new Error("Unsupported private argument type; verification stopped");
    }
  }
  return masked;
}

export function median(values) {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

export function summarize(records) {
  const groups = new Map();
  for (const record of records.filter(record => record.run >= 0)) {
    const key = `${record.version}/${record.fixture}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(record);
  }
  return [...groups.values()].map(group => {
    const result = { version: group[0].version, fixture: group[0].fixture, runs: group.length };
    for (const role of ["prove", "verify"]) {
      result[role] = Object.fromEntries(["preparationMs", "mainMs", "wallMs"].map(name =>
        [name, median(group.map(record => record[role][name]))]));
    }
    result.proofBytes = median(group.map(record => record.proofBytes));
    return result;
  });
}

export function sanitizedLines(content) {
  return String(content).replace(/\x1b\[[0-9;]*m/g, "").split(/\r?\n/)
    .filter(line => line && !/^args\s*:/i.test(line.trim()));
}

export function runWorker({ assetBase, role, config, proof, onLog = () => {},
                            onStatus = () => {}, timeoutMs = 180000,
                            WorkerClass = globalThis.Worker }) {
  return new Promise((resolve, reject) => {
    const started = performance.now();
    const logs = [];
    let worker;
    let timer;
    let settled = false;
    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      worker?.terminate();
      if (error) reject(error);
      else resolve({ ...result, wallMs: performance.now() - started, logs });
    };
    try {
      worker = new WorkerClass(new URL("payment_proof_worker.js", assetBase));
      timer = setTimeout(() => finish(new Error(`${role} timed out`)), timeoutMs);
      worker.onerror = event => {
        event.preventDefault?.();
        finish(new Error(event.message || "Payment worker failed"));
      };
      worker.onmessageerror = () => finish(new Error("Cannot read payment worker result"));
      worker.onmessage = ({ data }) => {
        if (settled) return;
        if (data.target === "error") {
          finish(new Error(data.message || "Payment worker failed"));
        } else if (data.target === "complete") {
          const validTimers = ["preparationMs", "mainMs", "workerMs"].every(name =>
            Number.isFinite(data[name]) && data[name] >= 0);
          if (!validTimers || (role === "prover" &&
              (!(data.proof instanceof Uint8Array) || data.proof.length === 0))) {
            finish(new Error("Invalid payment worker result"));
          } else finish(null, data);
        } else if (data.target === "status") {
          onStatus(String(data.value || ""));
        } else if (data.target === "stdout" || data.target === "stderr") {
          for (const line of sanitizedLines(data.content)) {
            logs.push(line);
            if (logs.length > 500) logs.shift();
            onLog(line);
          }
        }
      };
      const transfer = proof ? [proof.buffer] : [];
      worker.postMessage({ role, config, proof }, transfer);
    } catch (error) {
      finish(error);
    }
  });
}

function roleMetrics(result) {
  const timersMs = {};
  const ecdsaSeconds = {};
  const constraints = {};
  for (const line of result.logs) {
    let match = /^([\w. -]+):\s+(\d+(?:\.\d+)?)ms/.exec(line);
    if (match) timersMs[match[1].trim()] = Number(match[2]);
    match = /^(ECDSA [\w-]+ seconds):\s+([\d.e+-]+)/.exec(line);
    if (match) ecdsaSeconds[match[1]] = Number(match[2]);
    match = /^Num (Linear constraints|quadratic constraints):\s+(\d+)/.exec(line);
    if (match) constraints[match[1]] = Number(match[2]);
  }
  return {
    preparationMs: result.preparationMs,
    mainMs: result.mainMs,
    wallMs: result.wallMs,
    workerMs: result.workerMs,
    backendVersion: result.logs.find(line => /^ligero-prover\s/.test(line)) || null,
    timersMs,
    ecdsaSeconds,
    constraints,
    logs: result.logs,
  };
}

async function initializePage() {
  const status = document.querySelector("#status");
  const progress = document.querySelector("#progress");
  const logOutput = document.querySelector("#logs");
  const configResponse = await fetch("/config");
  if (!configResponse.ok) throw new Error("Cannot load benchmark configuration");
  const manifest = await configResponse.json();
  const { saveToken, ...metadata } = manifest;
  let report = {
    schemaVersion: 1,
    sessionId: manifest.sessionId,
    metadata,
    browser: {
      userAgent: navigator.userAgent,
      hardwareConcurrency: navigator.hardwareConcurrency,
      platform: navigator.platform,
    },
    records: [],
    medians: [],
    errors: [],
  };
  const previous = await fetch("/results").then(response => response.json());
  if (previous?.sessionId === manifest.sessionId) report = previous;
  const labels = new Map(manifest.variants.map(variant => [variant.id, variant.label]));
  const cases = new Map(manifest.cases.map(fixture => [fixture.id, fixture.label]));
  const buttons = [];
  let running = false;
  let progressValue = 0;
  const seconds = value => `${(value / 1000).toFixed(3)} s`;

  function addRow(parent, cells) {
    const row = document.createElement("tr");
    for (const value of cells) {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.append(cell);
    }
    parent.append(row);
  }

  function render() {
    report.medians = summarize(report.records);
    const medians = document.querySelector("#medians");
    const runs = document.querySelector("#runs");
    medians.replaceChildren();
    runs.replaceChildren();
    for (const row of report.medians) {
      addRow(medians, [labels.get(row.version), cases.get(row.fixture), `${row.runs}/3`,
        ...["prove", "verify"].flatMap(role => ["preparationMs", "mainMs", "wallMs"]
          .map(name => seconds(row[role][name])))]);
    }
    for (const row of report.records) {
      addRow(runs, [labels.get(row.version), cases.get(row.fixture),
        row.run < 0 ? "Warmup (excluded)" : row.run + 1,
        seconds(row.prove.mainMs), seconds(row.prove.wallMs),
        seconds(row.verify.mainMs), seconds(row.verify.wallMs), row.proofBytes.toLocaleString()]);
    }
  }

  async function save() {
    report.updatedAt = new Date().toISOString();
    const response = await fetch("/results", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Benchmark-Token": saveToken },
      body: JSON.stringify(report),
    });
    if (!response.ok) throw new Error("Cannot save benchmark JSON results");
  }

  async function benchmark(versionIds) {
    if (running) return;
    running = true;
    buttons.forEach(button => { button.disabled = true; });
    status.classList.remove("error");
    progressValue = 0;
    progress.max = versionIds.length * manifest.cases.length * (manifest.warmups + manifest.runs) * 2;
    progress.value = 0;
    try {
      for (const versionId of versionIds) {
        const variant = manifest.variants.find(item => item.id === versionId);
        if (!variant) throw new Error("Unknown benchmark version");
        report.records = report.records.filter(record => record.version !== versionId);
        render();
        for (const fixture of manifest.cases) {
          const response = await fetch(`/fixtures/${fixture.id}.json`);
          if (!response.ok) throw new Error("Cannot fetch payment fixture");
          const fixtureConfig = await response.json();
          for (let run = -manifest.warmups; run < manifest.runs; run += 1) {
            const config = structuredClone(fixtureConfig);
            config.program = "modules/payroll_verification.wasm";
            config["shader-path"] = "shader";
            config.packing = manifest.packing;
            delete config["commitment-cache-mb"];
            if (variant.commitmentCacheMb !== null) {
              config["commitment-cache-mb"] = variant.commitmentCacheMb;
            }
            // Fail before proving if a private input cannot be safely masked.
            const publicConfig = maskPrivateInputs(config);
            const label = `${variant.label} · ${fixture.label} · ${run < 0 ? "warmup" : `run ${run + 1}/3`}`;
            const logs = [];
            const options = {
              assetBase: new URL(variant.assetBase, location.href),
              onLog: line => {
                logs.push(line);
                logOutput.textContent = logs.slice(-30).join("\n");
              },
              onStatus: message => { status.textContent = `${label} · ${message}`; },
            };
            status.textContent = `${label} · preparing prover`;
            const prove = await runWorker({ ...options, role: "prover", config });
            progress.value = ++progressValue;
            const proofBytes = prove.proof.length;
            status.textContent = `${label} · preparing masked verifier`;
            const verify = await runWorker({ ...options, role: "verifier", config: publicConfig,
              proof: prove.proof });
            progress.value = ++progressValue;
            report.records.push({ version: versionId, fixture: fixture.id, run,
              commitmentCacheMb: variant.commitmentCacheMb,
              prove: roleMetrics(prove), verify: roleMetrics(verify), proofBytes,
              maskedVerification: true });
            render();
            await save();
          }
        }
      }
      status.textContent = "PASS: all requested proofs and masked-input verifications completed.";
    } catch (error) {
      status.classList.add("error");
      status.textContent = `FAIL: ${error.message}`;
      report.errors.push({ at: new Date().toISOString(), message: error.message });
      try { await save(); } catch { status.textContent += " Results could not be saved."; }
    } finally {
      running = false;
      buttons.forEach(button => { button.disabled = false; });
    }
  }

  for (const variant of manifest.variants) {
    const button = document.createElement("button");
    button.textContent = `Benchmark ${variant.label.toLowerCase()}`;
    button.addEventListener("click", () => benchmark([variant.id]));
    document.querySelector("#controls").append(button);
    buttons.push(button);
  }
  if (buttons.length > 1) {
    const button = document.createElement("button");
    button.textContent = "Benchmark all versions";
    button.addEventListener("click", () => benchmark(manifest.variants.map(variant => variant.id)));
    document.querySelector("#controls").append(button);
    buttons.push(button);
  }
  document.querySelector("#save-location").textContent = `Results save to ${manifest.resultFile}. Warmups are excluded from medians.`;
  render();
  if (!navigator.gpu) {
    buttons.forEach(button => { button.disabled = true; });
    status.textContent = "WebGPU is unavailable. Open this loopback URL in a browser with WebGPU enabled.";
  } else status.textContent = "Ready. Choose a version to benchmark.";
  // Convenient for local automation; the same overlap guard and checks apply.
  globalThis.runBenchmark = version => benchmark(Array.isArray(version) ? version : [version]);
}

if (typeof document !== "undefined") {
  initializePage().catch(error => {
    const status = document.querySelector("#status");
    status.classList.add("error");
    status.textContent = `Cannot start benchmark: ${error.message}`;
  });
}
