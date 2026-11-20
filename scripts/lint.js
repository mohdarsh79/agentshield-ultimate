#!/usr/bin/env node

const fs = require("fs");
const path = require("path");

const ROOT_DIR = path.resolve(__dirname, "..");
const TARGET_DIRS = ["src", "tests"];

let errorsFound = 0;
let filesInspected = 0;

const FORBIDDEN_PATTERNS = [
  { pattern: /\beval\s*\(/, message: "Forbidden use of eval()" },
  { pattern: /new\s+Function\s*\(/, message: "Forbidden use of new Function()" },
  { pattern: /\bdebugger\s*;?/, message: "Forgotten debugger statement" },
  { pattern: /catch\s*\([^)]*\)\s*\{\s*\}/, message: "Silent swallowed error in empty catch block" }
];

function checkFile(filePath) {
  filesInspected++;
  const content = fs.readFileSync(filePath, "utf-8");
  const lines = content.split("\n");

  lines.forEach((line, lineIndex) => {
    // Skip comment lines
    const trimmed = line.trim();
    if (trimmed.startsWith("//") || trimmed.startsWith("*")) return;

    for (const rule of FORBIDDEN_PATTERNS) {
      if (rule.pattern.test(line)) {
        console.error(`[LINT ERROR] ${path.relative(ROOT_DIR, filePath)}:${lineIndex + 1}: ${rule.message}`);
        console.error(`  > ${trimmed}`);
        errorsFound++;
      }
    }
  });
}

function traverse(dir) {
  if (!fs.existsSync(dir)) return;
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== "node_modules" && entry.name !== "dist") {
        traverse(full);
      }
    } else if (entry.isFile() && (entry.name.endsWith(".ts") || entry.name.endsWith(".js"))) {
      checkFile(full);
    }
  }
}

console.log("\n[*] Running AgentShield Ultimate strict static code quality analysis...");
TARGET_DIRS.forEach(dir => traverse(path.join(ROOT_DIR, dir)));

console.log(`[*] Inspected ${filesInspected} source files.`);
if (errorsFound > 0) {
  console.error(`[FAIL] Code quality audit failed with ${errorsFound} issues.`);
  process.exit(1);
} else {
  console.log(`[PASS] Code quality audit passed: 0 defects detected across all source units.\n`);
  process.exit(0);
}
