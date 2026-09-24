"use strict";

class ProtocolError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.name = "ProtocolError";
    this.code = code;
  }
}

function requireCondition(condition, code, message) {
  if (!condition) {
    throw new ProtocolError(code, message);
  }
}

module.exports = Object.freeze({ ProtocolError, requireCondition });
