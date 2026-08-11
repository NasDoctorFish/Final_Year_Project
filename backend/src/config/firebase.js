/**
 * Firebase Admin SDK setup.
 *
 * The Admin SDK runs with full privileges, so it bypasses Firestore security rules.
 * That means every access check in this API has to be enforced in our own code
 * (see middleware/auth.js). The rules in firestore.rules exist as a second line of
 * defence for any client that talks to Firestore directly.
 */
import { initializeApp, cert, applicationDefault, getApps } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getFirestore, FieldValue, Timestamp } from "firebase-admin/firestore";

import { env } from "./env.js";

function buildCredential() {
  if (env.firebase.projectId && env.firebase.clientEmail && env.firebase.privateKey) {
    return cert({
      projectId: env.firebase.projectId,
      clientEmail: env.firebase.clientEmail,
      privateKey: env.firebase.privateKey,
    });
  }
  // Falls back to Application Default Credentials: GOOGLE_APPLICATION_CREDENTIALS if
  // set, otherwise (on Cloud Run/Cloud Functions/GCE) the instance's own metadata
  // server, which the SDK queries automatically with no key on disk anywhere.
  return applicationDefault();
}

if (getApps().length === 0) {
  if (env.usingEmulators) {
    // The emulators authenticate nobody, so no credential is supplied. Passing one would
    // only force us to invent a valid-looking service account for tests.
    initializeApp({ projectId: env.firebase.projectId });
    console.log(`Firebase running against local emulators (project ${env.firebase.projectId}).`);
  } else {
    initializeApp({ credential: buildCredential() });
  }
}

export const auth = getAuth();
export const db = getFirestore();
export { FieldValue, Timestamp };

// Ignoring undefined properties keeps optional fields from throwing when a caller
// omits them, instead of forcing every write to strip its own undefined values.
db.settings({ ignoreUndefinedProperties: true });
