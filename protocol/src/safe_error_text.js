"use strict";

const SENSITIVE_ENVIRONMENT_VARIABLES = Object.freeze([
  "ARBITRUM_SEPOLIA_RPC_URL",
  "ARBITRUM_SEPOLIA_PRIVATE_KEY",
]);

function redactSensitiveErrorText(value, environment = process.env) {
  let result = String(value);
  for (const name of SENSITIVE_ENVIRONMENT_VARIABLES) {
    const secret = environment[name];
    if (typeof secret === "string" && secret.length > 0) {
      result = result.split(secret).join("[REDACTED]");
    }
  }
  return result;
}

module.exports = { redactSensitiveErrorText };
