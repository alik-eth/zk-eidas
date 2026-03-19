#!/usr/bin/env node
// Upload large circuit artifacts to UploadThing and save URLs to circuits/artifact-urls.json.
// Usage: UPLOADTHING_TOKEN=... node scripts/upload-artifacts.mjs
// Or:    source .env.production && node scripts/upload-artifacts.mjs

import { UTApi } from "uploadthing/server";
import { readFileSync, writeFileSync, existsSync } from "fs";
import { basename, join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const URLS_FILE = join(ROOT, "circuits", "artifact-urls.json");

const utapi = new UTApi({ token: process.env.UPLOADTHING_TOKEN });

const ARTIFACTS = [
  { path: "circuits/build/ecdsa_verify/ecdsa_verify.zkey", key: "ecdsa_verify_zkey" },
  { path: "circuits/build/ecdsa_verify_cvm/ecdsa_verify.cvm", key: "ecdsa_verify_cvm" },
];

// Load existing URLs
let urls = {};
if (existsSync(URLS_FILE)) {
  urls = JSON.parse(readFileSync(URLS_FILE, "utf8"));
}

for (const artifact of ARTIFACTS) {
  const fullPath = join(ROOT, artifact.path);
  if (!existsSync(fullPath)) {
    console.log(`SKIP ${artifact.path} (not found)`);
    continue;
  }

  const name = basename(fullPath);
  const data = readFileSync(fullPath);
  const file = new File([data], name);

  console.log(`Uploading ${name} (${(data.length / 1024 / 1024).toFixed(1)} MB)...`);
  const [result] = await utapi.uploadFiles([file]);

  if (result.error) {
    console.error(`FAIL ${name}: ${result.error.message}`);
    process.exit(1);
  }

  urls[artifact.key] = result.data.ufsUrl;
  console.log(`OK ${name} → ${result.data.ufsUrl}`);
}

// Static URLs (publicly hosted, no upload needed)
urls.ptau21 = "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_21.ptau";
urls.ptau22 = "https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_22.ptau";

writeFileSync(URLS_FILE, JSON.stringify(urls, null, 2) + "\n");
console.log(`\nSaved URLs to ${URLS_FILE}`);
