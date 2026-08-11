#!/usr/bin/env node
/**
 * One-shot: create every composite index in firestore.indexes.json against the real
 * project, using the service-account credential already in .env.
 *
 * Firestore refuses queries that combine an equality filter with orderBy on a
 * different field unless a matching composite index exists (see firestore.indexes.json
 * for why each one here is needed). The emulator does not enforce this, which is why
 * the app worked in local testing and then failed the moment it ran against real
 * Firestore. `firebase deploy --only firestore:indexes` is the normal way to apply
 * this file, but that needs an interactive `firebase login`; this script does the same
 * thing directly through the Firestore Admin API with the service-account key we
 * already have, so it can run unattended.
 *
 * Usage: node scripts/create-indexes.mjs
 */
import "dotenv/config";
import pkg from "@google-cloud/firestore";
const { v1 } = pkg;
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectId = process.env.FIREBASE_PROJECT_ID;
const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
const privateKey = (process.env.FIREBASE_PRIVATE_KEY || "").replace(/\\n/g, "\n");

if (!projectId || !clientEmail || !privateKey) {
  console.error("Missing FIREBASE_PROJECT_ID / FIREBASE_CLIENT_EMAIL / FIREBASE_PRIVATE_KEY in .env.");
  process.exit(1);
}

const client = new v1.FirestoreAdminClient({
  projectId,
  credentials: { client_email: clientEmail, private_key: privateKey },
});

const defsPath = path.join(__dirname, "..", "firestore.indexes.json");
const { indexes } = JSON.parse(readFileSync(defsPath, "utf-8"));

function fieldsMatch(existing, wanted) {
  if (existing.length !== wanted.length) return false;
  return existing.every((f, i) => {
    const order = f.order || (f.arrayConfig ? undefined : f.order);
    return f.fieldPath === wanted[i].fieldPath && order === wanted[i].order;
  });
}

async function main() {
  let created = 0;
  let already = 0;
  let failed = 0;

  for (const def of indexes) {
    const parent = client.collectionGroupPath(projectId, "(default)", def.collectionGroup);
    const label = `${def.collectionGroup}: ${def.fields.map((f) => `${f.fieldPath} ${f.order}`).join(", ")}`;

    try {
      const [existing] = await client.listIndexes({ parent });
      const dup = existing.find(
        (idx) => idx.queryScope === def.queryScope && fieldsMatch(idx.fields, def.fields)
      );
      if (dup) {
        console.log(`  already exists  ${label}`);
        already += 1;
        continue;
      }

      const [operation] = await client.createIndex({
        parent,
        index: { queryScope: def.queryScope, fields: def.fields },
      });
      console.log(`  creating...     ${label}`);
      await operation.promise();
      console.log(`  done            ${label}`);
      created += 1;
    } catch (err) {
      console.error(`  FAILED          ${label}\n    ${err.message}`);
      failed += 1;
    }
  }

  console.log(`\n${created} created, ${already} already existed, ${failed} failed.`);
  if (failed > 0) process.exit(1);
}

main();
