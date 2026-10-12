// Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
// One CPU-only runtime for a fixed or variable scalar-multiplication branch.
var Module;
let branch;
self.onmessage = ({data}) => {
  if (data.type === 'init') {
    if (Module || (data.part !== 0 && data.part !== 1)) {
      self.postMessage({type: 'error', message: 'Invalid witness worker initialization'});
      return;
    }
    branch = data.part;
    Module = {
      noInitialRun: true,
      locateFile: name => new URL(name, data.assetBase).href,
      print: () => {},
      printErr: message => console.error(message),
      onAbort: reason => self.postMessage({type: 'error', message: String(reason)}),
      onRuntimeInitialized: () => {
        if (Module._ligero_ecdsa_witness_prepare(branch) !== 0) {
          self.postMessage({type: 'error', message: 'ECDSA public table preparation failed'});
        } else {
          self.postMessage({type: 'ready'});
        }
      },
    };
    try {
      importScripts(new URL('ecdsa_witness.js', data.assetBase).href);
    } catch (error) {
      self.postMessage({type: 'error', message: error.message});
    }
  } else if (data.type === 'run') {
    try {
      const status = Module.callMain([String(branch), ...data.components]);
      if (status) throw new Error('Witness worker exited with status ' + status);
      const bytes = Module.FS.readFile('/witness-part.bin');
      Module.FS.unlink('/witness-part.bin');
      self.postMessage({type: 'complete', bytes}, [bytes.buffer]);
    } catch (error) {
      self.postMessage({type: 'error', message: error.message});
    }
  }
};
