/**
 * LangGraph orchestration for the AI explanation layer -- standalone build.
 *
 * NOT WIRED IN. Nothing in this file is imported anywhere else in the app yet, and this
 * file itself has no exports (see bottom). It exists to be exercised by the local
 * verification script only, until a human reviews it and decides to wire it up. Do not
 * import this file from a route or another service without that confirmation.
 *
 * Three rules carried over unchanged from gemini.service.js, which this file does not
 * modify and continues to run in production:
 *   - The model only ever explains a finding the rule-based scanner already confirmed.
 *     It never decides whether a vulnerability exists.
 *   - Every string a tool can return passes through egressGuard(), which redacts and
 *     caps it before it is appended to the message list Gemini sees on the next turn.
 *     Tool call ORDER never matters -- the boundary is each tool's return value, because
 *     LangGraph appends every ToolMessage to context and sends the whole thing back.
 *   - The prompt carries our own reviewed guidance (knowledgeBase.js) and the model is
 *     told to treat it as the authority, so the fix given out is one checked against
 *     MASVS, not one the model recalled.
 *
 * Egress policy for this file (agreed): derived facts (counts, category slugs, enums)
 * plus, for at most one named finding per tool call, its redacted evidence capped at
 * 800 characters. Never more than that per tool return. compare_scans strips evidence
 * entirely -- a diff needs categories, not two scans' worth of provider rows.
 */
import { StateGraph, START, END, Annotation } from "@langchain/langgraph";
import { z } from "zod";

import { env } from "../config/env.js";
import { ApiError } from "../utils/ApiError.js";
import { redact, redactFinding } from "../utils/redact.js";
import * as knowledgeBase from "./knowledgeBase.js";
import { getScanForCaller, compareScans } from "./scans.service.js";
import { SEVERITIES } from "../constants/index.js";

/* ------------------------------------------------------------------------------------ *
 * Model client -- reused config, not a new dependency on @langchain/google-genai. The
 * agent node calls @google/genai directly so retry behaviour, GEMINI_MODEL, and the key
 * resolution stay identical to gemini.service.js.
 * ------------------------------------------------------------------------------------ */

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

/** Retryable server-side conditions, copied verbatim from gemini.service.js. */
function isTransient(error) {
  const text = String(error?.message || "").toLowerCase();
  return ["503", "502", "500", "429", "unavailable", "overloaded", "high demand", "timeout"].some(
    (t) => text.includes(t)
  );
}

/* ------------------------------------------------------------------------------------ *
 * Egress guard -- the one place a value crosses from "our data" to "what Gemini sees".
 * Every tool below routes its return through this. Nothing bypasses it.
 * ------------------------------------------------------------------------------------ */

const EVIDENCE_CAP = 800;
const LABEL_CAP = 200;

function capString(value, cap) {
  if (typeof value !== "string") return value;
  const safe = redact(value);
  return safe.length > cap ? `${safe.slice(0, cap)}…[truncated]` : safe;
}

/**
 * Strip a value to an explicit allowlist of keys, redact and cap every string left, and
 * log what went out. `shape` maps each allowed key to a cap (0 or omitted = LABEL_CAP).
 */
function egressGuard(state, tool, value, shape) {
  let out;
  if (Array.isArray(value)) {
    out = value.map((item) => egressGuard(state, tool, item, shape));
  } else if (value && typeof value === "object") {
    out = {};
    for (const [key, cap] of Object.entries(shape)) {
      if (!(key in value)) continue;
      const raw = value[key];
      out[key] =
        typeof raw === "string"
          ? capString(raw, cap || LABEL_CAP)
          : raw && typeof raw === "object"
            ? egressGuard(state, tool, raw, shape[`${key}.`] || {})
            : raw;
    }
  } else {
    out = capString(value, LABEL_CAP);
  }

  const bytes = Buffer.byteLength(JSON.stringify(out) ?? "", "utf8");
  state.egressLog.push({ tool, bytes, at: Date.now() });
  return out;
}

/* ------------------------------------------------------------------------------------ *
 * Tools -- every return value passes through egressGuard. Args are model-supplied except
 * `user`, which is bound from the session closure and can never be named by the model.
 * ------------------------------------------------------------------------------------ */

function buildTools(state, { user, scanIds }) {
  const allowed = new Set(scanIds);

  async function fetchAllowedScan(scanId) {
    if (!allowed.has(scanId)) {
      throw ApiError.forbidden("That scan is not part of this session.");
    }
    return getScanForCaller(scanId, user);
  }

  return [
    {
      name: "get_scan_summary",
      description: "Get severity counts and metadata for one scan in this session.",
      schema: z.object({ scanId: z.string() }),
      async func({ scanId }) {
        const scan = await fetchAllowedScan(scanId);
        const value = {
          type: scan.type,
          counts: scan.counts,
          findingCount: scan.findingCount ?? (scan.findings ?? []).length,
          createdAt: scan.createdAt ?? null,
        };
        return JSON.stringify(egressGuard(state, "get_scan_summary", value, { type: 0 }));
      },
    },
    {
      name: "list_findings",
      description: "List every finding in a scan by index, category, severity, and component. No evidence.",
      schema: z.object({ scanId: z.string() }),
      async func({ scanId }) {
        const scan = await fetchAllowedScan(scanId);
        const value = (scan.findings ?? []).map((f, index) => ({
          index,
          category: f.category,
          severity: f.severity,
          component: f.component ?? null,
        }));
        return JSON.stringify(
          egressGuard(state, "list_findings", value, { category: 0, severity: 0, component: LABEL_CAP })
        );
      },
    },
    {
      name: "get_finding_evidence",
      description:
        "Get the redacted evidence for one named finding, capped at 800 characters. Use sparingly.",
      schema: z.object({ scanId: z.string(), findingIndex: z.number().int().min(0) }),
      async func({ scanId, findingIndex }) {
        const scan = await fetchAllowedScan(scanId);
        const finding = (scan.findings ?? [])[findingIndex];
        if (!finding) throw ApiError.notFound("That finding does not exist in this scan.");
        const safe = redactFinding(finding);
        const value = { category: safe.category, severity: safe.severity, evidence: safe.evidence };
        return JSON.stringify(
          egressGuard(state, "get_finding_evidence", value, {
            category: 0,
            severity: 0,
            evidence: EVIDENCE_CAP,
          })
        );
      },
    },
    {
      name: "get_guidance",
      description: "Get our own reviewed MASVS guidance for a finding category. Not app data.",
      schema: z.object({ category: z.string() }),
      async func({ category }) {
        const value = { section: knowledgeBase.promptSection(category) };
        return JSON.stringify(egressGuard(state, "get_guidance", value, { section: 4000 }));
      },
    },
    {
      name: "compare_scans",
      description:
        "Compare two scans of the same app by category. Evidence is never included in this tool's output.",
      schema: z.object({ baselineId: z.string(), currentId: z.string() }),
      async func({ baselineId, currentId }) {
        const [baseline, current] = await Promise.all([
          fetchAllowedScan(baselineId),
          fetchAllowedScan(currentId),
        ]);
        const raw = await compareScans(baseline, current);
        const stripFinding = (f) => ({ category: f.category, severity: f.severity, component: f.component ?? null });
        const value = {
          summary: raw.summary,
          resolved: raw.resolved.map(stripFinding),
          introduced: raw.introduced.map(stripFinding),
          unchanged: raw.unchanged.map(stripFinding),
        };
        return JSON.stringify(
          egressGuard(state, "compare_scans", value, { category: 0, severity: 0, component: LABEL_CAP })
        );
      },
    },
  ];
}

const TOOL_CALL_BUDGET = 8;

/* ------------------------------------------------------------------------------------ *
 * Modes -- each gets a system prompt (rules from gemini.service.js, shape enforced by
 * responseSchema so the model can't hand back malformed JSON) and a zod validator.
 * ------------------------------------------------------------------------------------ */

const BASE_RULES = `You explain confirmed Android security findings to app developers who are not security specialists.

Rules:
- Findings have already been confirmed by a rule-based scanner. Never question whether one is real, and never speculate about other problems.
- Where reviewed guidance is supplied for a finding's category (via the get_guidance tool), treat it as the authority: your fix must be the one it describes, and you must not contradict it or name APIs it does not mention.
- Write for a developer with no security background. Plain words, no jargon unless you define it in the same sentence.
- Be specific about the fix. Name the actual Android API, manifest attribute, or setting to change.
- Do not invent evidence, file names, or line numbers that are not returned by a tool.
- Use tools to gather what you need rather than assuming. Call get_guidance for the category before writing a fix.`;

const MODES = {
  explain: {
    systemPrompt: `${BASE_RULES}

You are explaining ONE finding. Call get_finding_evidence for it and get_guidance for its category, then respond. Keep the explanation to three sentences or fewer, and the fix to four sentences or fewer.`,
    schema: z.object({
      explanation: z.string().min(1),
      mitigation: z.string().min(1),
      references: z.array(z.string()).default([]),
    }),
  },
  synthesize: {
    systemPrompt: `${BASE_RULES}

You are summarising a whole scan. Call get_scan_summary and list_findings rather than assuming content. Identify which findings compound each other and what to fix first.`,
    schema: z.object({
      summary: z.string().min(1),
      priorities: z.array(z.object({ findingIndex: z.number().int().min(0), why: z.string().min(1) })),
      themes: z.array(z.string()).default([]),
    }),
  },
  compare: {
    systemPrompt: `${BASE_RULES}

You are narrating the difference between two scans of the same app. Call compare_scans. Say plainly what got fixed and what regressed.`,
    schema: z.object({
      narrative: z.string().min(1),
      regressions: z.array(z.string()).default([]),
      improvements: z.array(z.string()).default([]),
    }),
  },
  report: {
    systemPrompt: `${BASE_RULES}

You are writing a report for one scan. Call get_scan_summary and list_findings, and get_guidance for categories that need it. Produce a short executive summary and a section per theme, not per finding.`,
    schema: z.object({
      title: z.string().min(1),
      executiveSummary: z.string().min(1),
      sections: z.array(z.object({ heading: z.string().min(1), body: z.string().min(1) })),
    }),
  },
};

/* ------------------------------------------------------------------------------------ *
 * Graph state
 * ------------------------------------------------------------------------------------ */

const GraphState = Annotation.Root({
  mode: Annotation(),
  input: Annotation(),
  messages: Annotation({ reducer: (a, b) => a.concat(b), default: () => [] }),
  toolCallCount: Annotation({ reducer: (_a, b) => b, default: () => 0 }),
  egressLog: Annotation({ reducer: (a, b) => a.concat(b), default: () => [] }),
  result: Annotation(),
  repaired: Annotation({ reducer: (_a, b) => b, default: () => false }),
});

function parseModelJson(text) {
  const cleaned = String(text ?? "")
    .trim()
    .replace(/^```(?:json)?\s*/i, "")
    .replace(/\s*```$/, "");
  return JSON.parse(cleaned);
}

/**
 * Build a runnable graph for one mode, bound to one session's tools.
 *
 * Session-scoping lives here, not in the tools' own module scope: `user` and `scanIds`
 * are captured in this closure per call, so nothing about who is asking can be smuggled
 * in through a model-supplied argument.
 */
export function buildGraph({ mode, user, scanIds }) {
  const modeDef = MODES[mode];
  if (!modeDef) throw ApiError.badRequest(`Unknown AI graph mode: ${mode}`);

  const state = { egressLog: [] };
  const tools = buildTools(state, { user, scanIds });
  const toolMap = new Map(tools.map((t) => [t.name, t]));
  const toolDeclarations = tools.map((t) => ({
    name: t.name,
    description: t.description,
    parameters: zodToGeminiSchema(t.schema),
  }));

  async function callModel(contents, extraSystemNote) {
    const client = await loadClient();
    let delay = 800;
    const attempts = 3;
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      try {
        return await client.models.generateContent({
          model: env.gemini.model,
          contents,
          config: {
            systemInstruction: extraSystemNote
              ? `${modeDef.systemPrompt}\n\n${extraSystemNote}`
              : modeDef.systemPrompt,
            tools: [{ functionDeclarations: toolDeclarations }],
          },
        });
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

  async function agentNode(s) {
    const response = await callModel(s.messages);
    const candidate = response?.candidates?.[0];
    const parts = candidate?.content?.parts ?? [];
    const functionCalls = parts.filter((p) => p.functionCall).map((p) => p.functionCall);

    if (functionCalls.length > 0 && s.toolCallCount < TOOL_CALL_BUDGET) {
      return {
        messages: [{ role: "model", parts }],
        toolCallCount: s.toolCallCount + functionCalls.length,
        _pendingCalls: functionCalls,
      };
    }

    const text = response.text ?? parts.find((p) => p.text)?.text ?? "";
    return { messages: [{ role: "model", parts }], result: text };
  }

  async function toolsNode(s) {
    const pending = s._pendingCalls ?? [];
    const responses = [];
    for (const call of pending) {
      const tool = toolMap.get(call.name);
      let outputText;
      try {
        outputText = tool ? await tool.func(call.args ?? {}) : JSON.stringify({ error: "unknown tool" });
      } catch (error) {
        outputText = JSON.stringify({ error: error.message || "tool failed" });
      }
      responses.push({
        role: "user",
        parts: [{ functionResponse: { name: call.name, response: { content: outputText } } }],
      });
    }
    return { messages: responses };
  }

  function validateNode(s) {
    let parsed;
    try {
      parsed = parseModelJson(s.result);
    } catch {
      return { result: null };
    }
    const check = modeDef.schema.safeParse(parsed);
    return check.success ? { result: check.data } : { result: null };
  }

  async function repairNode(s) {
    if (s.repaired) {
      throw ApiError.internal("The AI service returned a response we could not read.");
    }
    return {
      repaired: true,
      messages: [
        {
          role: "user",
          parts: [
            {
              text: "That reply did not match the required JSON shape. Reply again with ONLY valid JSON matching the shape described in your instructions.",
            },
          ],
        },
      ],
    };
  }

  const graph = new StateGraph(GraphState)
    .addNode("agent", agentNode)
    .addNode("tools", toolsNode)
    .addNode("validate", validateNode)
    .addNode("repair", repairNode)
    .addEdge(START, "agent")
    .addConditionalEdges("agent", (s) => (s.result === undefined ? "tools" : "validate"), {
      tools: "tools",
      validate: "validate",
    })
    .addEdge("tools", "agent")
    .addConditionalEdges("validate", (s) => (s.result === null ? "repair" : "finish"), {
      repair: "repair",
      finish: END,
    })
    .addEdge("repair", "agent");

  const compiled = graph.compile();

  return {
    async invoke(userContent) {
      const initial = {
        mode,
        input: userContent,
        messages: [{ role: "user", parts: [{ text: userContent }] }],
      };
      const finalState = await compiled.invoke(initial);
      return {
        result: finalState.result,
        egressLog: state.egressLog,
        toolCallCount: finalState.toolCallCount ?? 0,
        model: env.gemini.model,
      };
    },
    egressLog: state.egressLog,
  };
}

/** Minimal zod-to-Gemini-function-schema translation for the shapes this file uses. */
function zodToGeminiSchema(schema) {
  const shape = schema._def.shape();
  const properties = {};
  const required = [];
  for (const [key, def] of Object.entries(shape)) {
    const isOptional = def.isOptional?.() ?? false;
    const inner = isOptional ? def._def.innerType : def;
    const typeName = inner._def.typeName;
    if (typeName === "ZodNumber") properties[key] = { type: "number" };
    else properties[key] = { type: "string" };
    if (!isOptional) required.push(key);
  }
  return { type: "object", properties, required };
}

/**
 * Build a session bound to one caller. `scanIds` is the allowlist of scans this session
 * may touch -- a tool call naming any other id is refused before Firestore is read.
 */
export function createSession({ user, scanIds }) {
  return {
    explain: (userContent) => buildGraph({ mode: "explain", user, scanIds }).invoke(userContent),
    synthesize: (userContent) => buildGraph({ mode: "synthesize", user, scanIds }).invoke(userContent),
    compare: (userContent) => buildGraph({ mode: "compare", user, scanIds }).invoke(userContent),
    report: (userContent) => buildGraph({ mode: "report", user, scanIds }).invoke(userContent),
  };
}

/*
 * Deliberately no default export and no side-effecting top-level calls. Importing this
 * module does nothing but define functions -- it is inert until createSession() is
 * called, and nothing in the app calls it yet.
 */
