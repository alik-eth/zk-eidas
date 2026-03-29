// circuits/scripts/split-zkey.mjs
// Splits a standard zkey into per-section chunk files for the chunked snarkjs fork.
//
// Usage: node scripts/split-zkey.mjs <input.zkey> [output-base-name]
// Example: node scripts/split-zkey.mjs build/ecdsa_verify/ecdsa_verify.zkey
//   → produces ecdsa_verify.zkeya, ecdsa_verify.zkeyb, ... ecdsa_verify.zkeyj

import * as binFileUtils from "@iden3/binfileutils";
import { createBinFile } from "@iden3/binfileutils";
import fs from "fs";

function sectionName(sectionId) {
  return String.fromCharCode("a".charCodeAt(0) + sectionId);
}

async function splitZkey(inputPath, outputBase) {
  if (!outputBase) {
    outputBase = inputPath.replace(/\.zkey$/, "");
  }

  console.log(`Reading ${inputPath}...`);
  const { fd, sections } = await binFileUtils.readBinFile(
    inputPath,
    "zkey",
    2,
    1 << 25,
    1 << 23
  );

  const sectionIds = Object.keys(sections).map(Number).sort((a, b) => a - b);
  console.log(`Found ${sectionIds.length} sections: ${sectionIds.join(", ")}`);

  for (const sectionId of sectionIds) {
    const suffix = sectionName(sectionId);
    const outPath = `${outputBase}.zkey${suffix}`;
    const type = "zky" + suffix;

    // Read section data from the original zkey
    const data = await binFileUtils.readSection(fd, sections, sectionId);

    // Write as a standalone chunk file matching the fork's format:
    // type(4 bytes) + version(ULE32) + nSections(ULE32) + size(ULE64) + data
    const fdOut = await createBinFile(outPath, type, 1, 1, 1 << 22, 1 << 24);
    await fdOut.writeULE64(data.byteLength);
    await fdOut.write(data);
    await fdOut.close();

    const sizeMB = (data.byteLength / (1024 * 1024)).toFixed(1);
    console.log(`  Section ${sectionId} → ${outPath} (${sizeMB} MB)`);
  }

  await fd.close();
  console.log("Done.");
}

const [inputPath] = process.argv.slice(2);
if (!inputPath) {
  console.error("Usage: node scripts/split-zkey.mjs <input.zkey> [output-base-name]");
  process.exit(1);
}
splitZkey(inputPath, process.argv[3]);
