/**
 * ESLint flat config.
 *
 * Deliberately the non-type-checked `recommended` set: `tsc --noEmit` is already
 * the type gate in CI and runs as its own step, so duplicating it inside the
 * linter would only make the lint step slower and its failures harder to read.
 * What lint adds here is the class of problem the compiler does not report —
 * unused bindings, accidental `any`, shadowed names, `==` vs `===`.
 */
import js from "@eslint/js";
import tseslint from "typescript-eslint";
import { createRequire } from 'module';

const require = createRequire(import.meta.url);

export default tseslint.config(
  { ignores: ["dist/**", "node_modules/**", "coverage/**", ".kilo/**"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.ts"],
    rules: {
      // TypeScript resolves identifiers itself; `no-undef` has no type
      // information and reports every Node global (process, Buffer, console)
      // as undefined in a typed codebase.
      "no-undef": "off",
      // `_`-prefixed parameters are intentional: the structural framework
      // adapters take arguments they must accept but do not all read.
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_", caughtErrorsIgnorePattern: "^_" },
      ],
    },
  },
  {
    // Plain-JS Node scripts have no tsconfig coverage, so `no-undef` cannot be
    // resolved by a type checker and needs the environment declared instead.
    files: ["scripts/**/*.mjs"],
    languageOptions: { globals: { process: "readonly", console: "readonly" } },
  },
);
