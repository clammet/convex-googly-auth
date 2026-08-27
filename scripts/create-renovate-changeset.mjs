import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dataFile = process.env.RENOVATE_POST_UPGRADE_COMMAND_DATA_FILE;

if (!dataFile) {
  throw new Error("Renovate did not provide post-upgrade command data");
}

const upgradeData = JSON.parse(await readFile(dataFile, "utf8"));
const packageJson = JSON.parse(
  await readFile(join(root, "package.json"), "utf8"),
);

// Only npm dependencies declared by this package warrant an npm release.
// Workflow action pins and lockfile-only maintenance do not change the package.
const upgrades = upgradeData
  .filter(({ packageFile }) => packageFile === "package.json")
  .filter(
    ({ depName, newValue, newVersion }) => depName && (newValue || newVersion),
  )
  .sort((left, right) => left.depName.localeCompare(right.depName));

if (upgrades.length === 0) {
  console.log("No package.json dependency updates; skipping npm changeset");
  process.exit(0);
}

const changes = upgrades.map(
  ({ currentValue, currentVersion, depName, newValue, newVersion }) => {
    const from = currentValue ?? currentVersion ?? "the previous version";
    const to = newValue ?? newVersion;
    return `Update dependency ${depName} from ${from} to ${to}.`;
  },
);
const summary = changes.length === 1 ? changes[0] : changes.join("\n");

// A major peer-dependency update can remove compatibility with consumers and
// therefore requires a major package release. Other dependency updates are
// implementation/build changes and become patch releases.
const releaseType = upgrades.some(
  ({ depType, updateType }) =>
    depType === "peerDependencies" && updateType === "major",
)
  ? "major"
  : "patch";

const identity = JSON.stringify(upgrades);
const suffix = createHash("sha256").update(identity).digest("hex").slice(0, 12);
const changesetDir = join(root, ".changeset");
const changesetFile = join(changesetDir, `renovate-${suffix}.md`);
const contents = `---\n"${packageJson.name}": ${releaseType}\n---\n\n${summary}\n`;

await mkdir(changesetDir, { recursive: true });
await writeFile(changesetFile, contents);
console.log(`Created ${changesetFile.slice(root.length + 1)}`);
