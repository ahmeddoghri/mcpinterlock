// The browser workbench decides locally, so its port must agree with the
// policy engine the CLI runs. This compares the two on every case below and
// fails on the first difference.
//
//     python3 -c "..."   # see run_parity.py, which drives this in CI
//     node tests/web_parity.mjs cases.json expected.json
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { analyze } = require("../mcpinterlock/web/policy.js");

const cases = JSON.parse(readFileSync(process.argv[2], "utf8"));
const expected = JSON.parse(readFileSync(process.argv[3], "utf8"));

let mismatches = 0;
cases.forEach((payload, i) => {
  let got;
  try {
    got = analyze(payload);
  } catch (error) {
    got = { error: error.message };
  }
  const want = expected[i];
  if (JSON.stringify(got) !== JSON.stringify(want)) {
    mismatches += 1;
    console.log(`case ${i} differs`);
    console.log("  python:", JSON.stringify(want));
    console.log("  js    :", JSON.stringify(got));
  }
});

console.log(`${cases.length - mismatches}/${cases.length} cases agree with the Python engine`);
process.exit(mismatches ? 1 : 0);
