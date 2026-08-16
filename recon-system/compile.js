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
 * directory containing a `solc` package, resolved via require()), and prints
 * the result to stdout as a single JSON document:
 *
 *   {
 *     "solc_version": "<version of the solc module actually loaded>",
 *     "solc_output": <solc Standard JSON Output>
 *   }
 *
 * The solc_version wrapper exists so the Python side can verify that the
 * compiler which actually ran is the version it resolved -- directory names
 * and module paths are never trusted as version evidence on their own.
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

// Version of the compiler module that will actually perform this
// compilation, as reported by the module itself (e.g. "0.8.28+commit.x").
// Fall back to the package manifest when the module doesn't expose semver().
let solcVersion = null;
try {
  solcVersion = typeof solc.semver === "function" ? solc.semver() : null;
} catch (err) {
  solcVersion = null;
}
if (!solcVersion) {
  try {
    solcVersion = require(path.join(path.dirname(require.resolve("solc", { paths: [solcModulePath] })), "package.json")).version;
  } catch (err) {
    solcVersion = null;
  }
}

let inputRaw;
try {
  inputRaw = fs.readFileSync(inputPath, "utf8");
} catch (err) {
  fail("failed to read standard-json input: " + err.message);
}

let solcOutput;
try {
  // No import callback: recon system pre-resolves all imports into the
  // standard-json `sources` map before invoking the compiler, so every
  // import should already be present. Missing imports surface as solc
  // errors in the output, which the Python side records as warnings.
  solcOutput = JSON.parse(solc.compile(inputRaw));
} catch (err) {
  fail("solc.compile threw: " + err.message);
}

process.stdout.write(JSON.stringify({ solc_version: solcVersion, solc_output: solcOutput }));
