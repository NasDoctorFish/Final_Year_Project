/**
 * Plain-language explanations for confirmed findings.
 *
 * Three rules govern this file. The model only ever explains a finding the desktop app's
 * own rules already confirmed, so it never decides what counts as a vulnerability. Every
 * string it receives is redacted first, so a token or key found inside an app cannot
 * reach a third party. And the prompt carries our own reviewed guidance for the finding's
 * category (see knowledgeBase.js), which the model is told to treat as the authority --
 * so the fix a developer is given is one we checked against MASVS, not one the model
 * recalled.
 *
 * The API key lives here on the server rather than in the desktop app, which means it
 * can be rotated centrally and is never shipped inside a downloadable binary.
 */
import { env } from "../config/env.js";
import { ApiError } from "../utils/ApiError.js";
import { redactFinding } from "../utils/redact.js";
import * as knowledgeBase from "./knowledgeBase.js";

const SYSTEM_PROMPT = `You explain confirmed Android security findings to app developers who are not security specialists.

Rules:
- The finding has already been confirmed by a rule-based scanner. Never question whether it is real, and never speculate about other problems.
- Where reviewed guidance is supplied for the finding's category, treat it as the authority: your fix must be the one it describes, and you must not contradict it or name APIs it does not mention.
- Write for a developer with no security background. Plain words, no jargon unless you define it in the same sentence.
- Be specific about the fix. Name the actual Android API, manifest attribute, or setting to change.
- Do not invent evidence, file names, or line numbers that are not in the input.
- Keep the explanation to three sentences or fewer, and the fix to four sentences or fewer.

Reply with JSON only, in this shape:
{"explanation": "...", "mitigation": "...", "references": ["..."]}`;

/** Retryable server-side conditions, as opposed to a bad request we should not repeat. */
function isTransient(error) {
  const text = String(error?.message || "").toLowerCase();
  return [
    "503", "502", "500", "429", "unavailable", "overloaded", "high demand",
    "timeout", "aborted", "abort",   // our own per-attempt deadline firing
  ].some((t) => text.includes(t));
}

async function loadClient() {
  if (!env.gemini.enabled) {
    throw ApiError.internal(
      "The AI explanation layer is not configured. Set GEMINI_API_KEY to enable it."
    );
  }
  try {
    const { GoogleGenAI } = await import("@google/genai");
    return new GoogleGenAI({ apiKey: env.gemini.apiKey });
  } catch {
    throw ApiError.internal(
      "The Gemini SDK is not installed. Run 'npm install @google/genai' to enable explanations."
    );
  }
}

function buildPrompt(finding) {
  const safe = redactFinding(finding);
  // Grounding comes first so the model reads the reviewed guidance before the finding it
  // has to apply it to. An unknown category yields an empty section and an ungrounded
  // prompt, which is a plainer answer rather than no answer.
  const grounding = knowledgeBase.promptSection(safe.category);

  return [
    grounding || null,
    grounding ? "" : null,
    `Category: ${safe.category}`,
    `Title: ${safe.title}`,
    `Severity: ${safe.severity}`,
    `OWASP risk codes: ${(safe.owasp ?? []).join(", ") || "not mapped"}`,
    `Confidence: ${safe.confidence ?? "confirmed"}`,
    safe.component ? `Affected component: ${safe.component}` : null,
    "",
    "Evidence captured by the scanner (secrets already removed):",
    safe.evidence,
  ]
    .filter((line) => line !== null)
    .join("\n");
}

function parseResponse(text) {
  // Models sometimes wrap JSON in a code fence even when asked not to.
  const cleaned = text
    .trim()
    .replace(/^```(?:json)?\s*/i, "")
    .replace(/\s*```$/, "");

  let parsed;
  try {
    parsed = JSON.parse(cleaned);
  } catch {
    throw ApiError.internal("The AI service returned a response we could not read.");
  }

  if (!parsed.explanation || !parsed.mitigation) {
    throw ApiError.internal("The AI service returned an incomplete explanation.");
  }

  return {
    explanation: String(parsed.explanation),
    mitigation: String(parsed.mitigation),
    references: Array.isArray(parsed.references) ? parsed.references.map(String) : [],
  };
}

/**
 * Generate an explanation and a fix for one finding.
 *
 * Retries a few times with a growing delay, because a busy model returning 503 is
 * common and a single failure should not lose the user's request.
 */
export async function explainFinding(finding, { attempts = 3 } = {}) {
  const client = await loadClient();
  const prompt = buildPrompt(finding);

  let delay = 800;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const response = await client.models.generateContent({
        model: env.gemini.model,
        contents: prompt,
        config: {
          systemInstruction: SYSTEM_PROMPT,
          responseMimeType: "application/json",
          // Bound each attempt. An overloaded model can otherwise leave the request
          // open for minutes before answering, which is worse than failing: the caller
          // has long since given up, and the retries below never get their turn.
          abortSignal: AbortSignal.timeout(env.gemini.timeoutMs),
        },
      });

      const text = response.text ?? response?.candidates?.[0]?.content?.parts?.[0]?.text ?? "";
      return { ...parseResponse(text), model: env.gemini.model };
    } catch (error) {
      const lastAttempt = attempt === attempts;
      if (lastAttempt || !isTransient(error)) {
        if (error instanceof ApiError) throw error;
        throw ApiError.internal(`The AI service is unavailable right now. ${error.message}`);
      }
      await new Promise((resolve) => setTimeout(resolve, delay));
      delay *= 2;
    }
  }

  throw ApiError.internal("The AI service is unavailable right now.");
}
