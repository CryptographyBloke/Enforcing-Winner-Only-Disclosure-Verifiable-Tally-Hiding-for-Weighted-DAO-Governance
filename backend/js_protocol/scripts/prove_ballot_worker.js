"use strict";

// One Groth16 ballot proof per process. The parent sends the witness over the IPC channel, never through argv or the
// environment (both are visible in the process list), and this process exits right after it answers.
//
// Why a separate process: a single snarkjs proof already spreads over many threads, but proofs started from the same
// process share one thread pool and run no faster than one after another. Separate processes each get their own pool
// and overlap the single-threaded witness computation of one proof with the multi-threaded proving of another.

const snarkjs = require("snarkjs");

process.once("message", async (message) => {
  try {
    const { input, wasmPath, zkeyPath } = message;
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasmPath, zkeyPath);
    process.send({ ok: true, proof, publicSignals }, () => process.exit(0));
  } catch (error) {
    process.send({ ok: false, message: String((error && error.message) || error) }, () => process.exit(1));
  }
});
