/**
 * PharmaSys Clinical Copilot
 * Safety-first, deterministic clinical reasoning layer.
 *
 * This module does NOT diagnose or prescribe. It performs:
 * - symptom risk screening
 * - structured follow-up questions
 * - medication-information routing
 * - emergency escalation
 * - visit-preparation guidance
 *
 * An external LLM can be placed above this layer later, while these
 * safety rules remain the final gate before a response reaches a user.
 */

const RED_FLAGS = [
  { id: "chest_pain", patterns: [/ألم.*صدر|الم.*صدر|chest pain/i], message: "ألم الصدر قد يحتاج تقييمًا عاجلًا، خصوصًا مع ضيق النفس أو التعرق أو الإغماء." },
  { id: "breathing", patterns: [/ضيق.*نفس|صعوبة.*تنفس|اختناق|can't breathe|shortness of breath/i], message: "صعوبة التنفس علامة تستدعي تقييمًا طبيًا عاجلًا." },
  { id: "stroke", patterns: [/ضعف.*وجه|ميل.*فم|صعوبة.*كلام|تنميل.*نصف|فقد.*حركة|stroke/i], message: "أعراض عصبية مفاجئة مثل ضعف جهة واحدة أو اضطراب الكلام تستدعي الطوارئ فورًا." },
  { id: "severe_bleeding", patterns: [/نزيف.*شديد|نزيف.*لا.*يتوقف|heavy bleeding/i], message: "النزيف الشديد أو الذي لا يتوقف يحتاج رعاية عاجلة." },
  { id: "anaphylaxis", patterns: [/تورم.*لسان|تورم.*حلق|صعوبة.*بلع.*تنفس|anaphylaxis/i], message: "تورم اللسان/الحلق مع صعوبة التنفس قد يكون تفاعلًا تحسسيًا شديدًا ويحتاج طوارئ." },
  { id: "unconscious", patterns: [/إغماء|فقد.*وعي|غير.*واع|unconscious|fainted/i], message: "فقدان الوعي يحتاج تقييمًا طبيًا، خصوصًا إذا كان مفاجئًا أو متكررًا." },
  { id: "seizure", patterns: [/تشنج|صرع.*مستمر|seizure/i], message: "التشنج المستمر أو المتكرر دون استعادة الوعي يحتاج طوارئ." }
];

const HIGH_RISK_CONTEXT = [
  { id: "pregnancy", patterns: [/حامل|حمل|pregnan/i], label: "الحمل" },
  { id: "child", patterns: [/طفل|رضيع|رضيعة|baby|infant|child/i], label: "طفل/رضيع" },
  { id: "elderly", patterns: [/كبير.*سن|مسن|elderly/i], label: "كبير سن" },
  { id: "anticoagulant", patterns: [/وارفارين|مميع|مضاد.*تجلط|anticoagulant|warfarin/i], label: "مضاد تخثر" },
  { id: "allergy", patterns: [/حساسية.*دواء|حساسية.*شديدة|drug allergy/i], label: "حساسية دوائية" }
];

const SYMPTOM_FOLLOWUPS = [
  "منذ متى بدأت الأعراض؟ وهل بدأت فجأة أم تدريجيًا؟",
  "ما شدة الأعراض من 0 إلى 10؟ وهل تزداد أم تتحسن؟",
  "هل توجد أعراض أخرى مصاحبة مثل حرارة، ضيق تنفس، قيء، نزيف أو إغماء؟",
  "هل لديك أمراض مزمنة أو حساسية دوائية أو أدوية تستخدمها حاليًا؟"
];

function textOf(input) {
  return String(input || "").trim();
}

function scanRedFlags(text) {
  return RED_FLAGS.filter(f => f.patterns.some(p => p.test(text)));
}

function scanContext(text) {
  return HIGH_RISK_CONTEXT.filter(f => f.patterns.some(p => p.test(text)));
}

function classify(text) {
  if (!text) return "unknown";
  if (scanRedFlags(text).length) return "urgent";
  if (/(دواء|علاج|حبوب|كبسول|شراب|مرهم|مضاد حيوي|دواء.*يتعارض|تداخل|interaction|medication)/i.test(text)) return "medication";
  if (/(عرض|أعراض|الم|ألم|وجع|حرارة|حمى|كحة|سعال|صداع|دوخة|مغص|قيء|إسهال|rash|symptom)/i.test(text)) return "symptoms";
  if (/(طبيب|دكتور|موعد|زيارة|appointment|doctor)/i.test(text)) return "visit_prep";
  return "general";
}

function assess(text) {
  const redFlags = scanRedFlags(text);
  const context = scanContext(text);

  if (redFlags.length) {
    return {
      level: "urgent",
      label: "تقييم عاجل",
      redFlags: redFlags.map(x => x.message),
      context: context.map(x => x.label),
      next: "إذا كانت الأعراض شديدة أو تتفاقم أو يوجد خطر فوري، تواصل مع خدمات الطوارئ المحلية أو اطلب تقييمًا طبيًا عاجلًا."
    };
  }

  if (context.length) {
    return {
      level: "caution",
      label: "يحتاج حذرًا إضافيًا",
      redFlags: [],
      context: context.map(x => x.label),
      next: "وجود عامل خطورة يغيّر القرار الدوائي؛ الأفضل مراجعة الطبيب/الصيدلي قبل استخدام دواء جديد."
    };
  }

  return { level: "routine", label: "معلومات عامة", redFlags: [], context: [], next: "يمكن متابعة جمع المعلومات قبل إعطاء أي توجيه عام." };
}

function responseFor(input) {
  const text = textOf(input);
  const intent = classify(text);
  const assessment = assess(text);

  if (intent === "urgent") {
    return {
      intent, assessment,
      message: `أفهم قلقك. ظهرت في رسالتك علامة قد تحتاج تقييمًا عاجلًا. ${assessment.redFlags.join(" ")} لا أستطيع تأكيد السبب عبر الدردشة.`,
      questions: [],
      actions: ["اطلب تقييمًا طبيًا عاجلًا إذا كانت الأعراض مستمرة/شديدة أو تتدهور."]
    };
  }

  if (intent === "symptoms") {
    return {
      intent, assessment,
      message: "أقدر أساعدك في فرز علامات الخطر وتنظيم المعلومات، لكن لا أستطيع تأكيد تشخيص من الدردشة. خلينا نحدد الصورة أولًا.",
      questions: SYMPTOM_FOLLOWUPS,
      actions: ["اذكر الأعراض الأساسية، مدة الأعراض، شدتها، والأدوية الحالية."]
    };
  }

  if (intent === "medication") {
    return {
      intent, assessment,
      message: "أستطيع شرح المعلومات العامة عن دواء أو البحث عنه داخل نظام الصيدلية. لا أختار جرعة شخصية ولا أغيّر علاجًا موصوفًا.",
      questions: [
        "ما اسم الدواء أو المادة الفعالة؟",
        "هل تريد معلومات عن الاستخدام العام، التحذيرات، الآثار الجانبية، أم التداخلات؟",
        "إذا كان السؤال عن شخص محدد: ما العمر وهل توجد حساسية/حمل/أدوية أخرى؟"
      ],
      actions: ["اكتب اسم الدواء كما هو على العبوة أو المادة الفعالة."]
    };
  }

  if (intent === "visit_prep") {
    return {
      intent, assessment,
      message: "ممتاز. أقدر أجهز لك ملخصًا مرتبًا للزيارة الطبية بدل محاولة التشخيص.",
      questions: [
        "ما المشكلة الأساسية ومتى بدأت؟",
        "ما الأعراض المصاحبة؟",
        "ما الأدوية والمكملات المستخدمة حاليًا؟",
        "ما أهم سؤال تريد إجابته من الطبيب؟"
      ],
      actions: ["بعد إجاباتك أرتبها في ملخص قصير قابل للعرض على الطبيب."]
    };
  }

  return {
    intent, assessment,
    message: "أنا PharmaSys Clinical Copilot. أساعد في معلومات الأدوية، فرز علامات الخطر، البحث داخل الصيدلية، وتجهيز أسئلة للطبيب أو الصيدلي.",
    questions: [],
    actions: ["اسأل عن دواء", "صف أعراضك", "اسأل عن علامات الخطر", "جهزني لزيارة الطبيب"]
  };
}

module.exports = { responseFor, assess, classify, scanRedFlags };
