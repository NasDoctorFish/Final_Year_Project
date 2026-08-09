/** Shared vocabulary. Keeping these in one place stops string typos from becoming bugs. */

export const COLLECTIONS = {
  USERS: "users",
  ORGANISATIONS: "organisations",
  INVITATIONS: "invitations",
  SCANS: "scans",
  FLAGS: "flags",
  AUDIT: "auditLog",
};

/** Billing tier. Controls which features a signed-in user may reach. */
export const TIERS = {
  FREE: "free",
  PREMIUM: "premium",
};

/** Role within an organisation. Separate from tier: an admin can be on either tier. */
export const ROLES = {
  MEMBER: "member",
  ADMIN: "admin",
};

export const SCAN_TYPES = {
  APK: "apk",
  DEVICE: "device",
};

export const INVITATION_STATUS = {
  PENDING: "pending",
  ACCEPTED: "accepted",
  CANCELLED: "cancelled",
  EXPIRED: "expired",
};

export const FLAG_STATUS = {
  OPEN: "open",
  REVIEWED: "reviewed",
  DISMISSED: "dismissed",
};

export const SUBSCRIPTION_STATUS = {
  NONE: "none",
  ACTIVE: "active",
  CANCELLING: "cancelling",
  CANCELLED: "cancelled",
};

/** Ordered so a report can sort most serious first. */
export const SEVERITIES = ["critical", "high", "medium", "low", "info"];

export const INVITATION_TTL_DAYS = 14;
