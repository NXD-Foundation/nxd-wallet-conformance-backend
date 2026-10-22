import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const REPOSITORY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cataloguePath = (environmentName, filename) => {
  const explicitPath = process.env[environmentName];
  if (explicitPath) return explicitPath;
  const catalogueRoot = process.env.FCAF_CATALOGUE_ROOT;
  if (catalogueRoot) return path.join(catalogueRoot, filename);
  return path.join(REPOSITORY_ROOT, "docs", "FCAFs", "catalogues", filename);
};
const CATALOGUES = [
  ["MessageStructure", cataloguePath("FCAF_MESSAGE_STRUCTURE_CATALOGUE_PATH", "fcaf-ms-specs-categorized.md")],
  ["SecurityMechanisms", cataloguePath("FCAF_SECURITY_MECHANISMS_CATALOGUE_PATH", "fcaf-sm-specs-categorized.md")],
];

function extractSpecs(markdown, layer) {
  return String(markdown).split(/^##\s+/m).slice(1).flatMap((section) => {
    const [title, ...body] = section.split(/\r?\n/);
    const subLayer = title.trim().split(/\s+\(/)[0];
    return body.flatMap((line) => {
      const match = line.match(/^\|\s*((?:[A-Za-z]+\s*)?\d{3}|[A-Za-z]+[_-]\d{3})\s*\|\s*([^|]+?)\s*\|/);
      if (!match) return [];
      const ref = match[1].replace(/\s+/g, "_");
      return [{ id: `${layer}.${subLayer}.${ref}`, layer, sub_layer: subLayer, description: match[2].trim() }];
    });
  });
}

function mainOverrides() {
  const path = process.env.FCAF_MAIN_OVERRIDES_PATH;
  if (!path) {
    throw new Error("Set FCAF_MAIN_OVERRIDES_PATH to main's we-build-cs02-disposition-overrides.json.");
  }
  return JSON.parse(fs.readFileSync(path, "utf8"));
}

const EVIDENCE_RULES = [
  { pattern: /state correlation|state mismatch|state missing|state.*valid|valid ascii.*state/i, implementation: ["utils/vpSessionCorrelation.js"], tests: ["tests/vpSessionCorrelation.test.js"] },
  { pattern: /transaction[_ ]data/i, implementation: ["wallet-client/src/lib/presentation.js", "wallet-client/src/lib/transactionDataKb.js"], tests: ["wallet-client/test/transactionDataKb.test.js"] },
  { pattern: /verifier attestation|va attestation|va jwt/i, implementation: ["utils/cryptoUtils.js"], tests: ["tests/directPostJwt.test.js"] },
  { pattern: /x\.509-based prefix|x509.*leaf cert/i, implementation: ["wallet-client/src/lib/presentation.js"], tests: ["wallet-client/test/authorizationRequestX509Hash.test.js"] },
  { pattern: /mso[_ -]mdoc|sd-jwt|sd[_ -]jwt|credential format/i, implementation: ["wallet-client/src/lib/presentation.js", "wallet-client/src/lib/dcqlCredentialSelection.js"], tests: ["wallet-client/test/dcqlCredentialSelection.test.js", "wallet-client/test/sdJwtDisclosureSelection.test.js"] },
  { pattern: /dcql|credential[_ ]set|claim[_ ]set|credential query/i, implementation: ["wallet-client/src/lib/dcqlCredentialSelection.js", "wallet-client/src/lib/presentation.js"], tests: ["wallet-client/test/dcqlCredentialSelection.test.js", "wallet-client/test/dcqlVpToken.test.js"] },
  { pattern: /direct[_ ]post|response mode|response jwt|jwe|encrypt|encryption/i, implementation: ["routes/verify/verifierRoutes.js", "utils/cryptoUtils.js"], tests: ["tests/directPostJwt.test.js", "tests/verifierEncryptionKeys.test.js"] },
  { pattern: /key binding|kb-jwt|cnf|nonce|audience/i, implementation: ["utils/sdJwtKeyBinding.js", "wallet-client/src/lib/presentationKeyBinding.js"], tests: ["tests/sdJwtKeyBinding.test.js"] },
  { pattern: /metadata|credential issuer|issuer metadata/i, implementation: ["routes/metadataroutes.js", "utils/issuerMetadataSigning.js"], tests: ["tests/metadataDiscovery.test.js", "tests/aptitudeProofMetadata.test.js"] },
];

const existing = (paths) => paths.filter((path) => fs.existsSync(path));

function structuralEvidence(description) {
  const text = description.toLowerCase();
  if (/trusted_authorit|trust mechanism|trust anchor|trusted list|aki/.test(text)) {
    return {
      implementation_paths: existing(["utils/routeUtils.js", "utils/keyAttestationProof.js"]),
      test_paths: existing(["tests/keyAttestationProof.test.js"]),
    };
  }
  if (/status.?list|revocation|mso revocation/.test(text)) {
    return {
      implementation_paths: existing(["utils/routeUtils.js", "utils/vpHeplers.js"]),
      test_paths: existing(["tests/wuaValidation.test.js"]),
    };
  }
  if (/x509|certificate|x5c/.test(text)) {
    return {
      implementation_paths: existing([
        "wallet-client/src/lib/presentation.js",
        "wallet-client/src/server.js",
        "routes/verify/vpStandardRoutes.js",
      ]),
      test_paths: existing(["wallet-client/test/authorizationRequestX509Hash.test.js", "tests/x509Routes.test.js"]),
    };
  }
  return { implementation_paths: [], test_paths: [] };
}

function branchDisposition(spec, mainEntry) {
  const sourceDisposition = mainEntry?.disposition;
  if (sourceDisposition === "inapplicable-cs02" || sourceDisposition === "out-of-scope-datamodel") {
    return {
      disposition: sourceDisposition,
      review_basis: "Profile exclusion/deferred data-model scope is unchanged on this branch.",
      implementation_paths: [],
      test_paths: [],
      remaining_gap: mainEntry?.remaining_gap || null,
    };
  }

  const text = spec.description.toLowerCase();
  if (/trust|trusted|certificate|x509|status.?list|revocation/.test(text)) {
    const evidence = structuralEvidence(spec.description);
    return {
      disposition: "structural-only",
      review_basis: "This branch has structural/key-material handling, but trust-authority or revocation decisions are intentionally incomplete.",
      implementation_paths: evidence.implementation_paths,
      test_paths: evidence.test_paths,
      remaining_gap: "Revalidate against configured trust anchors/status authorities when available.",
    };
  }

  const rule = EVIDENCE_RULES.find((candidate) => candidate.pattern.test(spec.description));
  const implementation_paths = rule ? existing(rule.implementation) : [];
  const test_paths = rule ? existing(rule.tests) : [];
  const hasCompleteEvidence = Boolean(rule && implementation_paths.length === rule.implementation.length && test_paths.length > 0);
  return {
    disposition: hasCompleteEvidence ? "implemented" : "partial",
    review_basis: hasCompleteEvidence
      ? "Branch-local runtime paths and focused tests were found for this requirement area."
      : "The requirement appears applicable, but branch-local enforcement or focused evidence is incomplete or cannot be mapped unambiguously from the catalogue description.",
    implementation_paths,
    test_paths,
    remaining_gap: hasCompleteEvidence ? null : "Add or map the missing branch-local enforcement and focused test evidence.",
  };
}

export function auditAptitudeFcafs() {
  const overrides = mainOverrides();
  const specs = CATALOGUES.flatMap(([layer, catalogueFile]) => {
    if (!fs.existsSync(catalogueFile)) {
      throw new Error(
        `FCAF catalogue for ${layer} was not found at ${catalogueFile}. ` +
        "Set FCAF_CATALOGUE_ROOT or the corresponding FCAF_*_CATALOGUE_PATH environment variable."
      );
    }
    return extractSpecs(fs.readFileSync(catalogueFile, "utf8"), layer);
  });
  const rows = specs.map((spec) => ({ ...spec, ...branchDisposition(spec, overrides[spec.id]) }));
  const counts = rows.reduce((out, row) => {
    out[row.disposition] = (out[row.disposition] || 0) + 1;
    return out;
  }, {});
  return { schema_version: "1.0", profile: "APTITUDE branch", evidence_bar: "implemented requires branch-local runtime paths and focused automated test evidence", rows, counts };
}

if (process.argv[1] && new URL(`file://${process.argv[1]}`).pathname === new URL(import.meta.url).pathname) {
  process.stdout.write(`${JSON.stringify(auditAptitudeFcafs(), null, 2)}\n`);
}
