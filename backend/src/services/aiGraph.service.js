/**
 * LangGraph orchestration for the AI explanation layer.
 *
 * Wired in: `createSession(...).explain(...)` is called from the finding-explain routes in
 * scans.routes.js and reports.routes.js, replacing the old single-shot gemini.service.js and
 * groq.service.js calls at those two sites. groq.service.js is left in the tree, unused --
 * nothing imports it anymore, Groq is reached through aiModelRouter.js's fallback chain
 * instead. The synthesize/compare/report modes below have no route wired to them yet.
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
import { redact, redactFinding, redactScope } from "../utils/redact.js";
import * as knowledgeBase from "./knowledgeBase.js";
import { getScanForCaller, compareScans } from "./scans.service.js";
import { SEVERITIES } from "../constants/index.js";
import { pickModels, recordSuccess, recordFailure } from "./aiModelRouter.js";

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
          scope: scan.scope ? redactScope(scan.scope) : null,
          createdAt: scan.createdAt ?? null,
        };
        return JSON.stringify(
          egressGuard(state, "get_scan_summary", value, {
            type: 0,
            "scope.": {
              deviceModel: 0,
              appVersion: 0,
              androidVersion: 0,
              loginState: 0,
              testsPerformed: 0,
            },
          })
        );
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

/**
 * Prompt registry -- one versioned entry per mode. `promptId`/`promptVersion` are
 * carried through to invoke()'s return value so a caller (or a future experiment
 * service) can tell which prompt produced a given result. Bump `promptVersion` on any
 * wording change to that mode's systemPrompt rather than editing it silently in place.
 */
const MODES = {
  explain: {
    promptId: "explain",
    promptVersion: "1.0.0",
    systemPrompt: `${BASE_RULES}

You are explaining ONE finding. Call get_finding_evidence for it and get_guidance for its category, then respond. Keep the explanation to three sentences or fewer, and the fix to four sentences or fewer.`,
    schema: z.object({
      explanation: z.string().min(1),
      mitigation: z.string().min(1),
      references: z.array(z.string()).default([]),
    }),
  },
  synthesize: {
    promptId: "synthesize",
    promptVersion: "1.0.0",
    systemPrompt: `${BASE_RULES}

You are summarising a whole scan. Call get_scan_summary and list_findings rather than assuming content. Identify which findings compound each other and what to fix first.`,
    schema: z.object({
      summary: z.string().min(1),
      priorities: z.array(z.object({ findingIndex: z.number().int().min(0), why: z.string().min(1) })),
      themes: z.array(z.string()).default([]),
    }),
  },
  compare: {
    promptId: "compare",
    promptVersion: "1.0.0",
    systemPrompt: `${BASE_RULES}

You are narrating the difference between two scans of the same app. Call compare_scans. Say plainly what got fixed and what regressed.`,
    schema: z.object({
      narrative: z.string().min(1),
      regressions: z.array(z.string()).default([]),
      improvements: z.array(z.string()).default([]),
    }),
  },
  report: {
    promptId: "report",
    promptVersion: "1.0.0",
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
  repairCount: Annotation({ reducer: (_a, b) => b, default: () => 0 }),
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
  let lastUsedEntry = null;
  const tools = buildTools(state, { user, scanIds });
  const toolMap = new Map(tools.map((t) => [t.name, t]));
  const toolDeclarations = tools.map((t) => ({
    name: t.name,
    description: t.description,
    parameters: zodToGeminiSchema(t.schema),
  }));

  /**
   * Provider-independent entry point. Tries each qualifying candidate for this mode in
   * route order (today: gemini:<model>, then any configured ollama:<model> as fallback).
   * A candidate that fails outright after its own retries records the failure against
   * its own circuit breaker and cedes to the next one; a non-transient error (bad
   * input, auth) is not retried across candidates since a different model won't fix it.
   */
  async function callModel(contents, extraSystemNote) {
    const systemPrompt = extraSystemNote
      ? `${modeDef.systemPrompt}\n\n${extraSystemNote}`
      : modeDef.systemPrompt;

    const candidates = pickModels(mode);
    if (candidates.length === 0) {
      throw ApiError.internal(`No healthy AI model available for mode: ${mode}`);
    }

    let lastError;
    for (const entry of candidates) {
      try {
        const result =
          entry.provider === "gemini"
            ? await callGemini(systemPrompt, contents)
            : entry.provider === "groq"
              ? await callGroqCloud(systemPrompt, contents)
              : entry.provider === "ollama"
                ? await callOllamaCloud(entry, systemPrompt, contents)
                : (() => {
                    // Reachable only once env.openai.enabled flips true; the registry
                    // still marks these entries enabled with no adapter behind them yet.
                    // Fail loudly here rather than silently skipping to the next candidate.
                    throw ApiError.internal(
                      `OpenAI is enabled in config but no call adapter is implemented yet for ${entry.id}.`
                    );
                  })();
        recordSuccess(entry.id);
        lastUsedEntry = entry;
        return result;
      } catch (error) {
        recordFailure(entry.id);
        lastError = error;
        if (error?.nonTransient) throw error;
        // else: exhausted this candidate's own retries on a transient condition -- try the next one.
      }
    }
    throw lastError instanceof ApiError
      ? lastError
      : ApiError.internal(`The AI service is unavailable right now. ${lastError?.message ?? ""}`);
  }

  /** Gemini call, normalized to { parts, text } so the rest of the graph is provider-agnostic. */
  async function callGemini(systemPrompt, contents) {
    const client = await loadClient();
    let delay = 800;
    const attempts = env.ai.maxProviderAttempts;
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      try {
        const response = await client.models.generateContent({
          model: env.gemini.model,
          contents,
          config: {
            systemInstruction: systemPrompt,
            tools: [{ functionDeclarations: toolDeclarations }],
          },
        });
        const parts = response?.candidates?.[0]?.content?.parts ?? [];
        const text = response.text ?? parts.find((p) => p.text)?.text ?? "";
        return { parts, text };
      } catch (error) {
        const lastAttempt = attempt === attempts;
        if (lastAttempt || !isTransient(error)) {
          const wrapped =
            error instanceof ApiError
              ? error
              : ApiError.internal(`The AI service is unavailable right now. ${error.message}`);
          wrapped.nonTransient = !isTransient(error);
          throw wrapped;
        }
        await new Promise((resolve) => setTimeout(resolve, delay));
        delay *= 2;
      }
    }
  }

  const GROQ_URL = "https://api.groq.com/openai/v1/chat/completions";

  /**
   * Groq's chat-completions endpoint. Groq is OpenAI-compatible, which is stricter than
   * Ollama's native API about tool calls: every assistant tool call needs an `id`, its
   * `arguments` must be a JSON string, and each tool result must carry the `tool_call_id`
   * it answers. So this uses its own translation (toOpenAIMessages /
   * normalizeOpenAIMessage below) rather than Ollama's. Sending Ollama's shape here
   * failed with `400: property 'id' is missing`.
   */
  async function callGroqCloud(systemPrompt, contents) {
    let delay = 800;
    const attempts = env.ai.maxProviderAttempts;
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      try {
        const response = await fetch(GROQ_URL, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${env.groq.apiKey}`,
          },
          signal: AbortSignal.timeout(env.groq.timeoutMs),
          body: JSON.stringify({
            model: env.groq.model,
            messages: toOpenAIMessages(systemPrompt, contents),
            tools: toOllamaTools(toolDeclarations),
          }),
        });
        if (!response.ok) {
          const body = await response.text().catch(() => "");
          const error = new Error(`Groq request failed (${response.status}): ${body.slice(0, 200)}`);
          error.status = response.status;
          throw error;
        }
        const data = await response.json();
        return normalizeOpenAIMessage(data?.choices?.[0]?.message);
      } catch (error) {
        // A 429 means the account's request quota is already spent for this window --
        // retrying immediately gets the same answer every time, so it is treated as
        // non-transient here rather than burning attempts on it.
        const transient =
          error.status !== 429 &&
          (error.name === "TimeoutError" ||
            error.name === "AbortError" ||
            [408, 425, 500, 502, 503, 504].includes(error.status) ||
            isTransient(error));
        const lastAttempt = attempt === attempts;
        if (lastAttempt || !transient) {
          const wrapped = ApiError.internal(`The Groq AI service is unavailable right now. ${error.message}`);
          wrapped.nonTransient = !transient;
          throw wrapped;
        }
        await new Promise((resolve) => setTimeout(resolve, delay));
        delay *= 2;
      }
    }
  }

  /**
   * Ollama Cloud call over its native /api/chat, translating our Gemini-shaped message
   * history and tool declarations to and from Ollama's OpenAI-style tool-call shape so
   * agentNode/toolsNode never need to know which provider answered.
   */
  async function callOllamaCloud(entry, systemPrompt, contents) {
    let delay = 800;
    const attempts = env.ai.maxProviderAttempts;
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      try {
        const response = await fetch(`${env.ollama.baseUrl.replace(/\/$/, "")}/api/chat`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(env.ollama.key ? { Authorization: `Bearer ${env.ollama.key}` } : {}),
          },
          signal: AbortSignal.timeout(env.ai.requestTimeoutMs),
          body: JSON.stringify({
            model: entry.model,
            stream: false,
            messages: toOllamaMessages(systemPrompt, contents),
            tools: toOllamaTools(toolDeclarations),
          }),
        });
        if (!response.ok) {
          const body = await response.text().catch(() => "");
          const error = new Error(`Ollama request failed (${response.status}): ${body.slice(0, 200)}`);
          error.status = response.status;
          throw error;
        }
        const data = await response.json();
        return normalizeOllamaMessage(data?.message);
      } catch (error) {
        const transient =
          error.name === "TimeoutError" ||
          error.name === "AbortError" ||
          [408, 425, 429, 500, 502, 503, 504].includes(error.status) ||
          isTransient(error);
        const lastAttempt = attempt === attempts;
        if (lastAttempt || !transient) {
          const wrapped = ApiError.internal(`The Ollama AI service is unavailable right now. ${error.message}`);
          wrapped.nonTransient = !transient;
          throw wrapped;
        }
        await new Promise((resolve) => setTimeout(resolve, delay));
        delay *= 2;
      }
    }
  }

  async function agentNode(s) {
    const { parts, text } = await callModel(s.messages);
    const functionCalls = parts.filter((p) => p.functionCall).map((p) => p.functionCall);

    if (functionCalls.length > 0 && s.toolCallCount < TOOL_CALL_BUDGET) {
      return {
        messages: [{ role: "model", parts }],
        toolCallCount: s.toolCallCount + functionCalls.length,
        _pendingCalls: functionCalls,
      };
    }

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

  const MAX_REPAIR_ATTEMPTS = 2;

  async function repairNode(s) {
    if (s.repairCount >= MAX_REPAIR_ATTEMPTS) {
      throw ApiError.internal("The AI service returned a response we could not read.");
    }
    return {
      repairCount: s.repairCount + 1,
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
      const startedAt = Date.now();
      const finalState = await compiled.invoke(initial);
      return {
        result: finalState.result,
        egressLog: state.egressLog,
        toolCallCount: finalState.toolCallCount ?? 0,
        promptId: modeDef.promptId,
        promptVersion: modeDef.promptVersion,
        provider: lastUsedEntry?.provider ?? null,
        model: lastUsedEntry?.model ?? env.gemini.model,
        latencyMs: Date.now() - startedAt,
      };
    },
    egressLog: state.egressLog,
  };
}

/** Our internal history is Gemini-shaped (role + parts); translate it for Ollama's /api/chat. */
function toOllamaMessages(systemPrompt, contents) {
  const messages = [{ role: "system", content: systemPrompt }];
  for (const turn of contents) {
    const role = turn.role === "model" ? "assistant" : "user";
    for (const part of turn.parts ?? []) {
      if (part.text) {
        messages.push({ role, content: part.text });
      } else if (part.functionCall) {
        messages.push({
          role: "assistant",
          content: "",
          tool_calls: [
            { function: { name: part.functionCall.name, arguments: part.functionCall.args ?? {} } },
          ],
        });
      } else if (part.functionResponse) {
        messages.push({
          role: "tool",
          content: JSON.stringify(part.functionResponse.response ?? {}),
        });
      }
    }
  }
  return messages;
}

/** Gemini functionDeclarations -> Ollama's OpenAI-style tool schema. */
function toOllamaTools(toolDeclarations) {
  return toolDeclarations.map((t) => ({
    type: "function",
    function: { name: t.name, description: t.description, parameters: t.parameters },
  }));
}

/** Ollama's chat message -> our internal { parts, text } shape. */
function normalizeOllamaMessage(message) {
  const parts = [];
  for (const call of message?.tool_calls ?? []) {
    parts.push({ functionCall: { name: call.function?.name, args: call.function?.arguments ?? {} } });
  }
  if (message?.content) parts.push({ text: message.content });
  return { parts, text: message?.content ?? "" };
}

/**
 * Gemini-shaped history -> OpenAI chat-completions messages (used for Groq).
 *
 * Unlike Ollama's native API, an OpenAI-compatible endpoint rejects a tool call that has
 * no `id`, arguments that are not a JSON string, and a tool result with no `tool_call_id`.
 * Our history carries none of those, so ids are made up here (or reused if the model
 * supplied one) and each tool result is paired with the oldest call still unanswered.
 * That matches how toolsNode answers calls: one response per call, in call order.
 * All the calls from one model turn go in a single assistant message, because the tool
 * results must follow the message that made the calls.
 */
function toOpenAIMessages(systemPrompt, contents) {
  const messages = [{ role: "system", content: systemPrompt }];
  const unanswered = [];
  let counter = 0;
  const nextId = () => `call_${(counter += 1)}`;

  for (const turn of contents) {
    const parts = turn.parts ?? [];
    if (turn.role === "model") {
      const text = parts
        .filter((p) => p.text)
        .map((p) => p.text)
        .join("");
      const toolCalls = parts
        .filter((p) => p.functionCall)
        .map((p) => {
          const id = p.functionCall.id || nextId();
          unanswered.push(id);
          return {
            id,
            type: "function",
            function: {
              name: p.functionCall.name,
              arguments: JSON.stringify(p.functionCall.args ?? {}),
            },
          };
        });
      messages.push({
        role: "assistant",
        content: text,
        ...(toolCalls.length > 0 ? { tool_calls: toolCalls } : {}),
      });
    } else {
      for (const part of parts) {
        if (part.functionResponse) {
          messages.push({
            role: "tool",
            tool_call_id: unanswered.shift() ?? nextId(),
            content: JSON.stringify(part.functionResponse.response ?? {}),
          });
        } else if (part.text) {
          messages.push({ role: "user", content: part.text });
        }
      }
    }
  }
  return messages;
}

/** An OpenAI-style assistant message -> our internal { parts, text } shape. */
function normalizeOpenAIMessage(message) {
  const parts = [];
  for (const call of message?.tool_calls ?? []) {
    // The API sends arguments as a JSON string; our tools expect an object.
    let args = call.function?.arguments ?? {};
    if (typeof args === "string") {
      try {
        args = JSON.parse(args || "{}");
      } catch {
        args = {};
      }
    }
    parts.push({ functionCall: { id: call.id, name: call.function?.name, args } });
  }
  if (message?.content) parts.push({ text: message.content });
  return { parts, text: message?.content ?? "" };
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
