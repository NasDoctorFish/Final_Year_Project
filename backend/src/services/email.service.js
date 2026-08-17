/**
 * Outbound notification email.
 *
 * Every function here is best-effort and never throws: an invitation that was created,
 * a password that was changed, an account that was removed -- those all already
 * succeeded by the time we try to send. Failing the request because a mail server was
 * unreachable would undo work that is done and correct, so send failures are logged and
 * swallowed instead.
 *
 * With no SMTP host configured the whole module becomes a no-op, which is what lets the
 * app run locally, in tests, and against the emulators without mail credentials.
 *
 * Note on invitations: BioAudit's client is a desktop app, so there is no web page for
 * an invite link to land on. The email carries the invitation *token*, which the
 * recipient pastes into the app's join dialog. The token is what the invite endpoint
 * already returns for the admin to pass on by hand -- emailing it just saves that step.
 */
import nodemailer from "nodemailer";

import { env } from "../config/env.js";

let transport = null;

function getTransport() {
  if (!env.email.enabled) return null;
  if (!transport) {
    transport = nodemailer.createTransport({
      host: env.email.host,
      port: env.email.port,
      // 465 is implicit TLS; anything else (typically 587) upgrades with STARTTLS.
      secure: env.email.port === 465,
      auth: { user: env.email.user, pass: env.email.pass },
    });
  }
  return transport;
}

/** Send one message. Resolves either way; returns whether it actually went out. */
async function send({ to, subject, text }) {
  const mailer = getTransport();
  if (!mailer) return false;

  try {
    await mailer.sendMail({ from: env.email.from, to, subject, text });
    return true;
  } catch (error) {
    // Deliberately not rethrown -- see the module docstring.
    console.error(`Could not send "${subject}" to ${to}: ${error.message}`);
    return false;
  }
}

export function sendInvitation({ to, organisationName, token, role, expiresInDays }) {
  const roleWording =
    role === "admin"
      ? "as an administrator, so you will be able to oversee the team's assessments"
      : "as a member";

  return send({
    to,
    subject: `You have been invited to ${organisationName} on BioAudit`,
    text: [
      `You have been invited to join ${organisationName} on BioAudit ${roleWording}.`,
      "",
      "To accept, open BioAudit, choose \"Join an organisation\" from the Account menu,",
      "and paste this invitation token:",
      "",
      `    ${token}`,
      "",
      `The token can be used once and expires in ${expiresInDays} days.`,
      "",
      "Joining lets the organisation's administrators see the assessments run from your",
      "account. If you were not expecting this invitation, you can ignore it -- nothing",
      "happens until you accept.",
    ].join("\n"),
  });
}

export function sendPasswordChanged({ to }) {
  return send({
    to,
    subject: "Your BioAudit password was changed",
    text: [
      "The password on your BioAudit account was just changed, and every other device",
      "signed in to this account has been signed out.",
      "",
      "If this was you, there is nothing to do.",
      "",
      "If it was not, someone else may have access to your account. Reset your password",
      "immediately and check your assessment history for activity you do not recognise.",
    ].join("\n"),
  });
}

export function sendRemovedFromOrganisation({ to, organisationName }) {
  return send({
    to,
    subject: `You are no longer part of ${organisationName} on BioAudit`,
    text: [
      `Your BioAudit account is no longer linked to ${organisationName}.`,
      "",
      "Your account itself is unaffected: it still exists, you keep your own free or",
      "premium status, and your assessment history stays with you. The organisation's",
      "administrators can no longer see it.",
    ].join("\n"),
  });
}

export function sendAccountDeletedByAdmin({ to, organisationName }) {
  return send({
    to,
    subject: "Your BioAudit account has been deleted",
    text: [
      `An administrator of ${organisationName} has deleted your BioAudit account.`,
      "",
      "Your assessment history has been permanently removed and you can no longer sign",
      "in. If you believe this was a mistake, contact your organisation's administrator.",
    ].join("\n"),
  });
}

export function sendAccountSuspended({ to, organisationName, suspended }) {
  return send({
    to,
    subject: suspended
      ? "Your BioAudit account has been suspended"
      : "Your BioAudit account has been reinstated",
    text: suspended
      ? [
          `An administrator of ${organisationName} has suspended your BioAudit account.`,
          "",
          "You have been signed out and cannot sign in again until the suspension is",
          "lifted. Your account and assessment history have not been deleted. Contact",
          "your organisation's administrator to find out why.",
        ].join("\n")
      : [
          `An administrator of ${organisationName} has lifted the suspension on your`,
          "BioAudit account. You can sign in again as normal.",
        ].join("\n"),
  });
}

export function sendMemberLeft({ to, memberEmail, organisationName }) {
  return send({
    to,
    subject: `A member deleted their BioAudit account (${organisationName})`,
    text: [
      `${memberEmail} has deleted their own BioAudit account and is therefore no longer`,
      `part of ${organisationName}.`,
      "",
      "This notice is for your records. A person can always delete their own account,",
      "and their assessment history is removed with it.",
    ].join("\n"),
  });
}
