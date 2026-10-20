// Keep the contrast claim in docs/ui-design.md executable. jsdom cannot
// calculate layout-based contrast, but the design tokens themselves can be
// checked directly against the actual CSS values on every CI run.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const css = readFileSync(new URL("../../src/checkstead/static/app.css", import.meta.url), "utf8");
const FOREGROUNDS = [
  "--ink", "--ink-soft", "--muted", "--verified", "--warn", "--fail",
  "--unknown", "--sev-critical", "--sev-high", "--sev-medium", "--sev-low",
  "--sev-none", "--focus", "--link",
];
const BACKGROUNDS = ["--paper", "--surface", "--surface-sunk"];

function tokenBlock(selector) {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = css.match(new RegExp(`(?:^|\\n)\\s*${escaped}\\s*\\{([^}]+)\\}`));
  assert.ok(match, `CSS token block not found: ${selector}`);
  return Object.fromEntries(
    [...match[1].matchAll(/(--[a-z-]+)\\s*:\\s*(#[0-9a-fA-F]{6})\\s*;/g)]
      .map(([, name, value]) => [name, value]),
  );
}

function rgb(hex) {
  return [1, 3, 5].map((index) => Number.parseInt(hex.slice(index, index + 2), 16) / 255);
}

function luminance(hex) {
  const [r, g, b] = rgb(hex).map((channel) =>
    channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4,
  );
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(foreground, background) {
  const values = [luminance(foreground), luminance(background)].sort((a, b) => b - a);
  return (values[0] + 0.05) / (values[1] + 0.05);
}

test("light and dark text tokens meet WCAG AA 4.5:1 against every app surface", () => {
  const themes = [
    ["light", tokenBlock(":root")],
    ["dark", tokenBlock(':root[data-theme="dark"]')],
  ];

  for (const [theme, tokens] of themes) {
    for (const name of [...FOREGROUNDS, ...BACKGROUNDS]) {
      assert.ok(tokens[name], `${theme} theme is missing ${name}`);
    }
    for (const foreground of FOREGROUNDS) {
      for (const background of BACKGROUNDS) {
        const ratio = contrast(tokens[foreground], tokens[background]);
        assert.ok(
          ratio >= 4.5,
          `${theme}: ${foreground} on ${background} is ${ratio.toFixed(2)}:1 (needs 4.5:1)`,
        );
      }
    }
  }
});
