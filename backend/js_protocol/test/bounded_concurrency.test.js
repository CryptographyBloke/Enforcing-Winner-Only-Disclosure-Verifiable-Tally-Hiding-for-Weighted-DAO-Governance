"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { mapWithLimit, ballotProofConcurrency } = require("../src/bounded_concurrency");

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

test("results keep the input order even when tasks finish out of order", async () => {
  const delays = [40, 5, 30, 1, 20, 10];
  const out = await mapWithLimit(delays, 3, async (delay, index) => { await sleep(delay); return `${index}:${delay}`; });
  assert.deepEqual(out, delays.map((delay, index) => `${index}:${delay}`));
});

test("never runs more than the limit at once, and does reach the limit", async () => {
  let running = 0;
  let peak = 0;
  await mapWithLimit(Array.from({ length: 12 }, (_, i) => i), 4, async () => {
    running += 1;
    peak = Math.max(peak, running);
    await sleep(8);
    running -= 1;
  });
  assert.equal(peak, 4);
});

test("limit 1 is strictly sequential", async () => {
  const order = [];
  await mapWithLimit([3, 2, 1], 1, async (x) => { order.push(`start${x}`); await sleep(x); order.push(`end${x}`); });
  assert.deepEqual(order, ["start3", "end3", "start2", "end2", "start1", "end1"]);
});

test("a limit above the item count still works and an empty list returns an empty array", async () => {
  assert.deepEqual(await mapWithLimit([1, 2], 50, async (x) => x * 2), [2, 4]);
  assert.deepEqual(await mapWithLimit([], 4, async () => 1), []);
});

test("the first error rejects, no new task starts afterwards, running tasks are awaited", async () => {
  const started = [];
  let finishedRunning = false;
  await assert.rejects(
    mapWithLimit([0, 1, 2, 3, 4, 5], 2, async (x) => {
      started.push(x);
      if (x === 0) { await sleep(2); throw new Error("boom"); }
      if (x === 1) { await sleep(25); finishedRunning = true; }
      return x;
    }),
    /boom/,
  );
  assert.equal(finishedRunning, true, "the task that was already running was awaited");
  assert.deepEqual(started, [0, 1], "no task was started after the failure");
});

test("invalid arguments are rejected", async () => {
  await assert.rejects(mapWithLimit("x", 2, async () => 1), TypeError);
  await assert.rejects(mapWithLimit([1], 0, async () => 1), RangeError);
  await assert.rejects(mapWithLimit([1], 1.5, async () => 1), RangeError);
  await assert.rejects(mapWithLimit([1], 2, null), TypeError);
});

test("ballotProofConcurrency defaults to 3 and validates the override", () => {
  assert.equal(ballotProofConcurrency({}), 3);
  assert.equal(ballotProofConcurrency({ CGY_BALLOT_PROOF_CONCURRENCY: "" }), 3);
  assert.equal(ballotProofConcurrency({ CGY_BALLOT_PROOF_CONCURRENCY: "1" }), 1);
  assert.equal(ballotProofConcurrency({ CGY_BALLOT_PROOF_CONCURRENCY: "8" }), 8);
  for (const bad of ["0", "-1", "2.5", "abc", "04", " 2"]) {
    assert.throws(() => ballotProofConcurrency({ CGY_BALLOT_PROOF_CONCURRENCY: bad }), RangeError, bad);
  }
});
