// Authenticate exported records, profile digests and manifests with REA's own
// production reader. This parses local evidence only and starts no provider.
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const args = process.argv.slice(2);
const reaIndex = args.indexOf("--rea-path");
const reaPath =
  reaIndex >= 0 ? args.splice(reaIndex, 2)[1] : "/opt/pcm-reversal/tools/rea";
if (!reaPath || args.length === 0) {
  throw new Error(
    "Usage: authenticate_bundles.mjs [--rea-path REA_CHECKOUT] EVIDENCE.json ...",
  );
}
const { parseEvidenceBundle } = await import(
  pathToFileURL(resolve(reaPath, "dist/domain/evidenceBundle.js")).href
);
const bundles = [];
for (const argument of args) {
  const path = resolve(argument);
  const parsed = parseEvidenceBundle(JSON.parse(await readFile(path, "utf8")));
  bundles.push({
    path,
    status: "authenticated",
    records: parsed.records.length,
    artifacts: parsed.artifacts.length,
  });
}
process.stdout.write(
  JSON.stringify({ status: "passed", bundles }, null, 2) + "\n",
);
