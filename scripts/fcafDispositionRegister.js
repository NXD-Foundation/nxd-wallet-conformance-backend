import fs from "fs";

export const DISPOSITIONS = new Set([
  "implemented", "partial", "structural-only", "inapplicable-cs02", "out-of-scope-datamodel",
]);

export function extractFcafSpecs(markdown, layer, subLayer) {
  const specs = [];
  for (const line of String(markdown).split(/\r?\n/)) {
    const match = line.match(/^\|\s*((?:[A-Za-z]+\s*)?\d{3}|[A-Za-z]+[_-]\d{3})\s*\|\s*([^|]+?)\s*\|/);
    if (!match) continue;
    const ref = match[1].replace(/\s+/g, "_");
    specs.push({ id: `${layer}.${subLayer}.${ref}`, layer, sub_layer: subLayer, description: match[2].trim() });
  }
  return specs;
}

export function buildDispositionRegister(specs, mapping) {
  const byId = mapping || {};
  const missing = specs.filter((spec) => !byId[spec.id]);
  if (missing.length) throw new Error(`Missing disposition mappings: ${missing.slice(0, 5).map((s) => s.id).join(", ")}`);
  return specs.map((spec) => {
    const entry = byId[spec.id];
    if (!DISPOSITIONS.has(entry.disposition)) throw new Error(`Invalid disposition for ${spec.id}`);
    return { ...spec, ...entry, remaining_gap: entry.remaining_gap ?? null };
  });
}

export function createDispositionTemplate(specs, existing = {}) {
  return Object.fromEntries(specs.map((spec) => [
    spec.id,
    existing[spec.id] || {
      disposition: null,
      we_build_rationale: "Requires explicit implementation/evidence classification.",
      implementation_paths: [],
      test_paths: [],
      remaining_gap: "Unclassified",
    },
  ]));
}

export function summarizeDispositionTemplate(template) {
  const counts = { implemented: 0, partial: 0, "structural-only": 0, "inapplicable-cs02": 0, "out-of-scope-datamodel": 0, unclassified: 0 };
  for (const entry of Object.values(template)) counts[entry.disposition || "unclassified"] += 1;
  return { ...counts, total: Object.keys(template).length, classified: Object.keys(template).length - counts.unclassified };
}

export function summarizeDispositionByLayer(template) {
  const layers = {};
  for (const [id, entry] of Object.entries(template)) {
    const layer = entry.layer || String(id).split(".")[0] || "Unknown";
    layers[layer] ||= {};
    const bucket = entry.disposition || "unclassified";
    layers[layer][bucket] = (layers[layer][bucket] || 0) + 1;
    layers[layer].total = (layers[layer].total || 0) + 1;
  }
  for (const counts of Object.values(layers)) counts.classified = counts.total - (counts.unclassified || 0);
  return layers;
}

export function loadMarkdown(path) { return fs.readFileSync(path, "utf8"); }
export function extractCategorizedSpecs(markdown, layer) {
  const sections = String(markdown).split(/^##\s+/m).slice(1);
  return sections.flatMap((section) => {
    const [title, ...body] = section.split(/\r?\n/);
    return extractFcafSpecs(body.join("\n"), layer, title.trim().split(/\s+\(/)[0]);
  });
}

if (process.argv[1] && new URL(`file://${process.argv[1]}`).pathname === new URL(import.meta.url).pathname) {
  const sources = [
    ["MessageStructure", "Catalogue", "/home/ni/code/fcafs/message-structure-analysis/fcaf-ms-specs-categorized.md"],
    ["SecurityMechanisms", "Catalogue", "/home/ni/code/fcafs/security-mechanism-analysis/fcaf-sm-specs-categorized.md"],
  ];
  const specs = sources.flatMap(([layer, , path]) => extractCategorizedSpecs(loadMarkdown(path), layer));
  const overridesPath = new URL("../FCAFs/we-build-cs02-disposition-overrides.json", import.meta.url);
  const overrides = JSON.parse(fs.readFileSync(overridesPath, "utf8"));
  const template = createDispositionTemplate(specs, overrides);
  const output = process.argv.includes("--by-layer")
    ? summarizeDispositionByLayer(template)
    : process.argv.includes("--summary")
      ? summarizeDispositionTemplate(template)
      : template;
  process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
}
