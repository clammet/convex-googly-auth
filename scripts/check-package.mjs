import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const packageJson = JSON.parse(
  readFileSync(join(root, "package.json"), "utf8"),
);
const errors = [];

function collectTargets(value) {
  if (typeof value === "string") return [value];
  if (!value || typeof value !== "object") return [];
  return Object.values(value).flatMap(collectTargets);
}

if (packageJson.private) errors.push("package.json must not be private");
if (packageJson.publishConfig?.registry !== "https://registry.npmjs.org/") {
  errors.push("publishConfig.registry must be the public npm registry");
}
if (packageJson.publishConfig?.access !== "public") {
  errors.push("publishConfig.access must be public");
}

const exportTargets = collectTargets(packageJson.exports);
for (const target of exportTargets) {
  if (!target.startsWith("./")) {
    errors.push(`export target must be package-relative: ${target}`);
  } else if (!existsSync(join(root, target))) {
    errors.push(`export target does not exist after build: ${target}`);
  }
}

const packOutput = execFileSync(
  "npm",
  ["pack", "--dry-run", "--json", "--ignore-scripts"],
  {
    cwd: root,
    encoding: "utf8",
    env: {
      ...process.env,
      npm_config_cache: join(
        tmpdir(),
        "convex-googly-auth-package-check-cache",
      ),
    },
  },
);
const [packResult] = JSON.parse(packOutput);
const packedFiles = new Set(packResult.files.map(({ path }) => path));

for (const target of exportTargets) {
  const packedPath = target.replace(/^\.\//, "");
  if (!packedFiles.has(packedPath)) {
    errors.push(`export target is missing from the package tarball: ${target}`);
  }
}

const requiredFiles = [
  "LICENSE",
  "README.md",
  "package.json",
  "dist/client/index.js",
  "dist/client/index.d.ts",
  "dist/react/index.js",
  "dist/react/index.d.ts",
  "dist/component/convex.config.js",
  "dist/component/_generated/component.d.ts",
  "src/test.ts",
  "src/component/schema.ts",
  "src/component/lib.ts",
];
for (const path of requiredFiles) {
  if (!packedFiles.has(path))
    errors.push(`required package file is missing: ${path}`);
}

for (const path of packedFiles) {
  if (path.includes(".test.") || path.endsWith("/setup.test.ts")) {
    errors.push(`test-only source leaked into the package: ${path}`);
  }
}

const clientEntry = await import(packageJson.name);
const reactEntry = await import(`${packageJson.name}/react`);
const componentEntry = await import(`${packageJson.name}/convex.config.js`);
if (typeof clientEntry.GooglyAuth !== "function") {
  errors.push("the root runtime export does not expose GooglyAuth");
}
if (typeof reactEntry.createGooglyAuthClient !== "function") {
  errors.push(
    "the React runtime export does not expose createGooglyAuthClient",
  );
}
if (!componentEntry.default) {
  errors.push("the Convex component config has no default runtime export");
}

if (errors.length > 0) {
  console.error(errors.map((error) => `- ${error}`).join("\n"));
  process.exitCode = 1;
} else {
  console.log(
    `Package contract OK: ${packResult.name}@${packResult.version}, ${packResult.entryCount} files, ${packResult.size} bytes packed.`,
  );
}
