// Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
// Load with importScripts in the fresh worker that owns the proving runtime.
// Public preparation can overlap loading webgpu_prover.js/webgpu_verifier.js.
globalThis.LigeroEcdsaR1cs = {
  precompute({assetBase, prover = false, parallel = true}) {
    const base = new URL(assetBase, globalThis.location.href).href;
    const useWorkers = prover && parallel;
    const workers = [];
    let closed = false;
    let attached = false;
    let busy = false;
    let callback;
    const pending = new Set();

    function request(worker, message, expected) {
      return new Promise((resolve, reject) => {
        const fail = error => { pending.delete(fail); reject(error); };
        pending.add(fail);
        worker.onerror = event => {
          fail(new Error(event.message || 'ECDSA worker failed'));
          dispose();
        };
        worker.onmessage = ({data}) => {
          if (data.type === 'error') { fail(new Error(data.message)); dispose(); }
          else if (data.type === expected) { pending.delete(fail); resolve(data); }
        };
        worker.postMessage(message);
      });
    }

    function dispose() {
      if (closed) return;
      closed = true;
      for (const worker of workers) worker.terminate();
      for (const reject of pending) reject(new Error('ECDSA precomputation disposed'));
      pending.clear();
      if (callback && globalThis.ligeroGenerateEcdsaWitness === callback) {
        delete globalThis.ligeroGenerateEcdsaWitness;
      }
    }

    const ready = Promise.all([
      (async () => {
        const response = await fetch(new URL('ecdsa_secp256k1_v1.r1cs.gz', base));
        if (!response.ok) throw new Error('Cannot fetch ECDSA constraint template');
        const expectedSize = 111833276;
        const bytes = new Uint8Array(expectedSize);
        const reader = response.body.pipeThrough(new DecompressionStream('gzip')).getReader();
        let offset = 0;
        try {
          for (;;) {
            const {done, value} = await reader.read();
            if (done) break;
            if (closed || value.length > expectedSize - offset) {
              throw new Error('ECDSA template disposed or oversized');
            }
            bytes.set(value, offset);
            offset += value.length;
          }
        } finally { await reader.cancel(); }
        if (offset !== expectedSize) throw new Error('Unexpected ECDSA template size');
        return bytes;
      })(),
      useWorkers ? Promise.all([0, 1].map(part => {
        const worker = new Worker(new URL('ecdsa_witness_worker.js', base));
        workers.push(worker);
        return request(worker, {type: 'init', assetBase: base, part}, 'ready');
      })) : Promise.resolve(),
    ]);
    // Mark early failures handled while the caller is still loading its runtime.
    ready.catch(dispose);

    return {
      async prepare(module) {
        if (attached || closed) throw new Error('Use one ECDSA preparation per fresh runtime');
        attached = true;
        try {
          const [template] = await ready;
          if (closed) throw new Error('ECDSA precomputation disposed');
          module.FS.writeFile('/ecdsa_secp256k1_v1.r1cs', template);
          module.ENV.LIGETRON_ECDSA_TEMPLATE = '/ecdsa_secp256k1_v1.r1cs';
          module.ENV.LIGETRON_ECDSA_PARALLEL = useWorkers ? '1' : '0';
          if (module._ligero_ecdsa_prepare(prover ? (parallel ? 2 : 1) : 0) !== 0) {
            throw new Error('ECDSA template validation failed');
          }
          module.FS.unlink('/ecdsa_secp256k1_v1.r1cs');
          if (useWorkers) {
            callback = async input => {
              if (closed || busy) throw new Error('ECDSA worker runtime is unavailable or busy');
              busy = true;
              try {
                const components = input.trim().split('\n');
                if (components.length !== 5 || components.some(x => !/^[0-9a-f]{1,64}$/i.test(x))) {
                  throw new Error('Invalid ECDSA worker input');
                }
                const results = await Promise.all(workers.map(worker =>
                  request(worker, {type: 'run', components}, 'complete')));
                if (closed) throw new Error('ECDSA worker runtime disposed');
                results.forEach((result, part) => module.FS.writeFile(
                  part ? '/witness-variable.bin' : '/witness-fixed.bin', result.bytes));
              } finally { busy = false; }
            };
            globalThis.ligeroGenerateEcdsaWitness = callback;
          }
        } catch (error) { dispose(); throw error; }
      },
      dispose,
    };
  },
};
