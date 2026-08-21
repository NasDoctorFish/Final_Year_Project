import fs from "node:fs";
const key = fs.readFileSync("./.env","utf-8").split("\n")
  .find(l=>l.startsWith("GEMINI_API_KEY=")).split("=")[1].trim();
const { GoogleGenAI } = await import("@google/genai");
const c = new GoogleGenAI({ apiKey: key });
const { promptSection } = await import("./src/services/knowledgeBase.js");

// Same shape of prompt the real explain endpoint sends, grounding included.
const prompt = promptSection("debuggable-release") +
  "\n\nCategory: debuggable-release\nTitle: Application is debuggable\nSeverity: high\n" +
  "OWASP risk codes: M8\nConfidence: confirmed\n\nEvidence captured by the scanner:\n" +
  'android:debuggable="true" in the manifest';

for (let i = 1; i <= 3; i++) {
  const t0 = Date.now();
  try {
    const r = await c.models.generateContent({
      model: "gemini-flash-latest",
      contents: prompt,
      config: { responseMimeType: "application/json" },
    });
    console.log(`  call ${i}: ${((Date.now()-t0)/1000).toFixed(1)}s  ok (${(r.text||"").length} chars)`);
  } catch (e) {
    console.log(`  call ${i}: ${((Date.now()-t0)/1000).toFixed(1)}s  FAILED: ${e.message.slice(0,90)}`);
  }
}
