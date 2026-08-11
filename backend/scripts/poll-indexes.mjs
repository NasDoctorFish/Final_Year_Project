#!/usr/bin/env node
/** Poll until every composite index in firestore.indexes.json reaches READY. */
import "dotenv/config";
import pkg from "@google-cloud/firestore";
const { v1 } = pkg;

const client = new v1.FirestoreAdminClient({
  projectId: process.env.FIREBASE_PROJECT_ID,
  credentials: {
    client_email: process.env.FIREBASE_CLIENT_EMAIL,
    private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
  },
});

async function snapshot() {
  const parent = client.collectionGroupPath(process.env.FIREBASE_PROJECT_ID, "(default)", "scans");
  const [indexes] = await client.listIndexes({ parent });
  const composites = indexes.filter((i) => i.fields.length > 1);
  const notReady = composites.filter((i) => i.state !== "READY");
  return { total: composites.length, notReady: notReady.length };
}

async function main() {
  for (let i = 0; i < 60; i++) {
    const { total, notReady } = await snapshot();
    if (notReady === 0 && total > 0) {
      console.log(`all ${total} composite indexes are READY`);
      process.exit(0);
    }
    console.log(`${total - notReady}/${total} ready, waiting...`);
    await new Promise((r) => setTimeout(r, 20000));
  }
  console.log("timed out waiting for indexes to build");
  process.exit(1);
}
main();
