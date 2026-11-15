"use strict";

/**
 * Run `task(item, index)` for every item with at most `limit` tasks in flight and return the results in the
 * original item order. A rejected task stops scheduling new work and rejects the returned promise with the first
 * error, after the tasks that are already running have settled, so no task is left running unobserved.
 *
 * This is deliberately tiny and dependency free: it is used to prove several Groth16 ballots at once, where the
 * order of the returned records must equal the order of the ballots on the board.
 */
async function mapWithLimit(items, limit, task) {
  if (!Array.isArray(items)) throw new TypeError("mapWithLimit: items must be an array");
  if (!Number.isInteger(limit) || limit < 1) throw new RangeError("mapWithLimit: limit must be a positive integer");
  if (typeof task !== "function") throw new TypeError("mapWithLimit: task must be a function");
  const results = new Array(items.length);
  let next = 0;
  let failed = false;
  let firstError;
  async function worker() {
    while (!failed) {
      const index = next;
      next += 1;
      if (index >= items.length) return;
      try {
        results[index] = await task(items[index], index);
      } catch (error) {
        if (!failed) {
          failed = true;
          firstError = error;
        }
        return;
      }
    }
  }
  const workers = [];
  for (let i = 0; i < Math.min(limit, items.length); i += 1) workers.push(worker());
  await Promise.all(workers);
  if (failed) throw firstError;
  return results;
}

/**
 * Number of ballot proofs to run at the same time. One snarkjs proof already uses about eleven cores on a
 * 24-thread host, so a small number is enough: measured on that host, 3 was fastest for eight ballots and 6 was
 * slower than 2. Override with CGY_BALLOT_PROOF_CONCURRENCY (a positive integer). Use 1 for the original
 * one-proof-at-a-time behaviour in the current process.
 */
function ballotProofConcurrency(env = process.env) {
  const raw = env.CGY_BALLOT_PROOF_CONCURRENCY;
  if (raw === undefined || raw === "") return 3;
  if (!/^[1-9][0-9]*$/.test(raw)) {
    throw new RangeError(`CGY_BALLOT_PROOF_CONCURRENCY must be a positive integer, got ${JSON.stringify(raw)}`);
  }
  return Number(raw);
}

module.exports = Object.freeze({ mapWithLimit, ballotProofConcurrency });
