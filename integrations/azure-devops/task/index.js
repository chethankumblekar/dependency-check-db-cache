"use strict";

const { spawnSync } = require("child_process");

const DEFAULT_IMAGE =
  "ghcr.io/chethankumblekar/dependency-check-db-cache/checkstead:0.1.0";

function reject(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(label + " is required.");
  }
  if (/[\0\r\n]/.test(value)) {
    throw new Error(label + " contains a newline.");
  }
}

function relativeTo(root, value) {
  const prefix = root.endsWith("/") ? root : root + "/";
  if (value === root) {
    return ".";
  }
  if (value.startsWith(prefix)) {
    return value.slice(prefix.length);
  }
  return value;
}

function assertInside(value, label) {
  reject(value, label);
  const parts = value.split(/[/\\]/).filter(Boolean);
  if (parts.includes("..")) {
    throw new Error(label + " cannot leave the sources directory.");
  }
}

function buildArgs(sources, inputs) {
  reject(sources, "sources");
  const image = inputs.image || DEFAULT_IMAGE;
  reject(image, "image");
  if (/[\0\r\n ]/.test(image)) {
    throw new Error("image contains unsupported characters.");
  }
  const scan = relativeTo(sources, inputs.scan || ".");
  const output = relativeTo(sources, inputs.output || "checkstead-report");
  assertInside(scan, "scan");
  assertInside(output, "output");
  const args = [
    "run",
    "--rm",
    "-v",
    sources + ":/work",
    "-w",
    "/work",
    image,
    "scan",
    "--scan",
    scan,
    "--out",
    output,
  ];
  if (inputs.project) {
    reject(inputs.project, "project");
    args.push("--project", inputs.project);
  }
  if (inputs.config) {
    const config = relativeTo(sources, inputs.config);
    assertInside(config, "config");
    args.push("--config", config);
  }
  return args;
}

function main() {
  const sources =
    process.env.BUILD_SOURCESDIRECTORY ||
    process.env.SYSTEM_DEFAULTWORKINGDIRECTORY ||
    process.cwd();
  let args;
  try {
    args = buildArgs(sources, {
      scan: process.env.INPUT_SCAN || ".",
      project: process.env.INPUT_PROJECT || "",
      output: process.env.INPUT_OUTPUT || "checkstead-report",
      config: process.env.INPUT_CONFIG || "",
      image: process.env.INPUT_IMAGE || DEFAULT_IMAGE,
    });
  } catch (error) {
    console.error("##vso[task.logissue type=error]" + error.message);
    process.exit(1);
  }
  const result = spawnSync("docker", args, { stdio: "inherit" });
  if (result.error) {
    console.error("##vso[task.logissue type=error]" + result.error.message);
    process.exit(1);
  }
  process.exit(result.status === null ? 1 : result.status);
}

if (require.main === module) {
  main();
} else {
  module.exports = { buildArgs, DEFAULT_IMAGE };
}
