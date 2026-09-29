/**
 * Cross-editor hygiene and line-ending invariants (issue #152).
 *
 * Asserts the presence and baseline properties of `.editorconfig` and `.gitattributes`
 * so contributors' editors and Git checkouts maintain consistent LF line endings
 * and indentation without cross-platform CRLF churn.
 */
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, it } from "node:test";

describe("editor and line-ending hygiene", () => {
  const rootDir = process.cwd();

  it("defines .editorconfig with formatter-mirrored baseline settings and hierarchy comment", () => {
    const editorConfigPath = resolve(rootDir, ".editorconfig");
    const content = readFileSync(editorConfigPath, "utf-8");

    assert.ok(
      content.includes("formatter is authoritative; this file assists editors only"),
      "editorconfig must include hierarchy comment clarifying formatter is authoritative",
    );
    assert.match(content, /^root\s*=\s*true/m, "editorconfig must declare root = true");
    assert.match(content, /indent_style\s*=\s*space/, "must declare space indent");
    assert.match(content, /indent_size\s*=\s*2/, "must declare 2-space indent");
    assert.match(content, /end_of_line\s*=\s*lf/, "must declare LF line endings");
    assert.match(content, /insert_final_newline\s*=\s*true/, "must declare final newline");
  });

  it("defines .gitattributes with universal LF checkout normalization", () => {
    const gitAttributesPath = resolve(rootDir, ".gitattributes");
    const content = readFileSync(gitAttributesPath, "utf-8");

    assert.match(
      content,
      /\*\s+text=auto\s+eol=lf/,
      "gitattributes must specify `* text=auto eol=lf`",
    );
  });

  it("verifies no tracked source files in src/ contain CRLF line endings", () => {
    const srcDir = resolve(rootDir, "src");
    const entries = readdirSync(srcDir);

    for (const entry of entries) {
      const fullPath = join(srcDir, entry);
      if (statSync(fullPath).isFile() && entry.endsWith(".ts")) {
        const fileContent = readFileSync(fullPath, "utf-8");
        assert.ok(
          !fileContent.includes("\r\n"),
          `file src/${entry} contains CRLF line ending (\r\n)`,
        );
      }
    }
  });
});
