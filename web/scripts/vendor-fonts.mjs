// Copy the Latin font subsets the UI uses from the pinned npm packages into
// src/checkstead/static/fonts. The lockfile's integrity hashes pin the
// packages; this records each copied file's SHA-256 in fonts/SHA256SUMS.
// With --check it copies nothing and fails when a vendored file differs.
import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, "..", "..", "src", "checkstead", "static", "fonts");
const files = [
  ["@fontsource/atkinson-hyperlegible-next", "atkinson-hyperlegible-next-latin-400-normal.woff2"],
  ["@fontsource/atkinson-hyperlegible-next", "atkinson-hyperlegible-next-latin-600-normal.woff2"],
  ["@fontsource/atkinson-hyperlegible-next", "atkinson-hyperlegible-next-latin-700-normal.woff2"],
  ["@fontsource/jetbrains-mono", "jetbrains-mono-latin-400-normal.woff2"],
  ["@fontsource/jetbrains-mono", "jetbrains-mono-latin-500-normal.woff2"],
];
const check = process.argv.includes("--check");
const digest = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
if (check) {
  let bad = 0;
  for (const [pkg, name] of files) {
    const want = digest(join(here, "..", "node_modules", pkg, "files", name));
    let have = "";
    try {
      have = digest(join(out, name));
    } catch {
      have = "missing";
    }
    if (have !== want) {
      console.error(`${name}: vendored ${have}, package ${want}. Run npm run vendor-fonts.`);
      bad += 1;
    }
  }
  if (bad) process.exit(1);
  console.log(`${files.length} vendored fonts match the pinned packages.`);
  process.exit(0);
}
mkdirSync(out, { recursive: true });
const sums = [];
for (const [pkg, name] of files) {
  const source = join(here, "..", "node_modules", pkg, "files", name);
  copyFileSync(source, join(out, name));
  sums.push(`${createHash("sha256").update(readFileSync(source)).digest("hex")}  ${name}`);
}
copyFileSync(join(here, "..", "node_modules", "@fontsource/atkinson-hyperlegible-next", "LICENSE"), join(out, "OFL-atkinson-hyperlegible-next.txt"));
copyFileSync(join(here, "..", "node_modules", "@fontsource/jetbrains-mono", "LICENSE"), join(out, "OFL-jetbrains-mono.txt"));
writeFileSync(join(out, "SHA256SUMS"), sums.join("\n") + "\n");
console.log(sums.join("\n"));
