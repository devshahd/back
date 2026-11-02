const { responseFor } = require("./clinical-copilot-engine");
const cases = [
  ["ألم صدر مع ضيق نفس", "urgent"],
  ["أنا حامل وأريد دواء", "medication"],
  ["عندي صداع من يومين", "symptoms"],
  ["أريد تجهيز أسئلة للطبيب", "visit_prep"]
];
for (const [input, expected] of cases) {
  const out = responseFor(input);
  if (out.intent !== expected) {
    throw new Error(`Expected ${expected}, got ${out.intent} for ${input}`);
  }
}
console.log("Clinical Copilot tests: OK");
