#!/usr/bin/env node
/**
 * compile.js
 *
 * Thin, deterministic wrapper around solc-js.
 *
 * Usage:
 *   node compile.js <solc_module_path> <standard_json_input_path>
 *
 * Reads a Solidity "Standard JSON Input" document from <standard_json_input_path>,
 * compiles it with the solc module located at <solc_module_path> (a path to a
 * directory containing a `solc` package, resolved via require()), and prints the
 * resulting Standard JSON Output to stdout as a single JSON document.
 *
 * This script performs NO analysis. It is purely a compiler invocation shim so
 * that the Python side of the Recon system can obtain solc's AST / source maps
 * without depending on a native solc binary (which is not fetchable in this
 * sandboxed network environment). solc-js ships as pure JS/WASM and is
 * self-contained once installed from npm.
 */
"use strict";

const fs = require("fs");
const path = require("path");

function fail(message) {
  process.stderr.write(String(message) + "\n");
  process.exit(1);
}

const [, , solcModulePath, inputPath] = process.argv;

if (!solcModulePath || !inputPath) {
  fail("usage: node compile.js <solc_module_path> <standard_json_input_path>");
}

let solc;
try {
  const resolved = require.resolve("solc", { paths: [solcModulePath] });
  solc = require(resolved);
} catch (err) {
  fail("failed to load solc module from " + solcModulePath + ": " + err.message);
}

let inputRaw;
try {
  inputRaw = fs.readFileSync(inputPath, "utf8");
} catch (err) {
  fail("failed to read standard-json input: " + err.message);
}

let outputRaw;
try {
  // No import callback: recon system pre-resolves all imports into the
  // standard-json `sources` map before invoking the compiler, so every
  // import should already be present. Missing imports surface as solc
  // errors in the output, which the Python side records as warnings.
  outputRaw = solc.compile(inputRaw);
} catch (err) {
  fail("solc.compile threw: " + err.message);
}

process.stdout.write(outputRaw);
