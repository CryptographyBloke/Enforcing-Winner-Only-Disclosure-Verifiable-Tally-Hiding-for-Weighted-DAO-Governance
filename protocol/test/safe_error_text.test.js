"use strict";

const assert = require("node:assert/strict");
const { test } = require("node:test");
const { redactSensitiveErrorText } = require("../src/safe_error_text");

test("redacts RPC credentials and deployer keys from provider errors", () => {
  const environment = {
    ARBITRUM_SEPOLIA_RPC_URL: "https://rpc.example.invalid/key/secret-token",
    ARBITRUM_SEPOLIA_PRIVATE_KEY: `0x${"a".repeat(64)}`,
  };
  const message = `request failed at ${environment.ARBITRUM_SEPOLIA_RPC_URL}; key=${environment.ARBITRUM_SEPOLIA_PRIVATE_KEY}`;
  const redacted = redactSensitiveErrorText(message, environment);
  assert.equal(redacted.includes(environment.ARBITRUM_SEPOLIA_RPC_URL), false);
  assert.equal(redacted.includes(environment.ARBITRUM_SEPOLIA_PRIVATE_KEY), false);
  assert.equal(redacted, "request failed at [REDACTED]; key=[REDACTED]");
});
