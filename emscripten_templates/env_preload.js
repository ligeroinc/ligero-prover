// Copy the host process environment into Emscripten's ENV before main() runs.
//
// Emscripten's getenv() reads its own internal ENV object, which is seeded with
// fixed defaults and does NOT inherit Node's process.env. Without this, running
//   LIGERO_REQUIRE_GPU=1 node webgpu_prover.js ...
// leaves getenv("LIGERO_REQUIRE_GPU") unset, silently disabling the GPU-required
// hard-fail (see src/webgpu/device_context.cpp, ligetron#387). Browsers have no
// process.env, so this is a no-op there. ENV is exported via
// EXPORTED_RUNTIME_METHODS so Module["ENV"] stays reachable under minification.
Module["preRun"] = Module["preRun"] || [];
Module["preRun"].push(function () {
  if (typeof process !== "undefined" && process.env && Module["ENV"]) {
    for (var key in process.env) {
      Module["ENV"][key] = process.env[key];
    }
  }
});
