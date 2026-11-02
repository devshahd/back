"""Safe pharmacy/clinical assistant for PharmaSys.

This module deliberately does NOT diagnose or prescribe.  It provides:
- pharmacy inventory/product lookup
- structured symptom triage and red-flag detection
- safe medication-information guidance
- Arabic (including common Egyptian spellings) normalization

The backend remains the source of truth; the frontend never fabricates clinical answers.
"""
from datetime import date
import re
from typing import List

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session

try:
    from .app.database import get_db
    from .app.models import Product
    from .app.security import current_user
except ImportError:  # pragma: no cover
    from app.database import get_db
    from app.models import Product
    from app.security import current_user

router = APIRouter(prefix="/chatbot", tags=["Clinical & Pharmacy Assistant"])


class ChatMessage(BaseModel):
    message: str = Field(min_length=1, max_length=2000)


class ChatResponse(BaseModel):
    reply: str
    intent: str
    safety_level: str = "normal"
    suggestions: List[str] = Field(default_factory=list)
    matched_products: List[dict] = Field(default_factory=list)
    disclaimer: str = "هذا المساعد لا يستبدل الطبيب أو الصيدلي ولا يصف علاجًا أو جرعات شخصية."


def normalize_ar(text: str) -> str:
    text = (text or "").strip().lower()
    text = re.sub(r"[إأآٱا]", "ا", text)
    text = text.replace("ى", "ي").replace("ة", "ه").replace("ؤ", "و").replace("ئ", "ي")
    text = re.sub(r"[ًٌٍَُِّْـ]", "", text)
    return re.sub(r"\s+", " ", text)


def product_dict(p: Product) -> dict:
    return {
        "id": p.id,
        "name": p.name,
        "price": float(p.selling_price or 0),
        "quantity": int(p.quantity or 0),
        "unit": p.unit,
        "barcode": p.barcode,
        "manufacturer": p.manufacturer,
        "expiry_date": p.expiry_date.isoformat() if p.expiry_date else None,
    }


# Red flags should win over every other intent.
RED_FLAG_GROUPS = {
    "تنفس/صدر": r"ضيق\s+(?:في\s+)?(?:ال)?تنفس|صعوبه\s+(?:في\s+)?(?:ال)?تنفس|مش\s+قادر\s+(?:اتنفس|يتنفس)|مش\s+عارف\s+اتنفس|نهجان\s+شديد|اختناق|ازرقاق|(?:الم|وجع|ضغط)\s+(?:في\s+)?(?:ال)?صدر|وجع\s+في\s+صدري|ضغط\s+شديد\s+(?:في\s+)?الصدر",
    "وعي/أعصاب": r"فقدان الوعي|اغماء|تشنج|تشنجات|شلل|ضعف مفاجئ|لخبطه كلام|صعوبه كلام|اعوجاج الوجه",
    "نزيف": r"نزيف شديد|نزيف لا يتوقف|دم كثير|قيء دموي|براز اسود مع دوخه",
    "حساسية شديدة": r"حساسيه\s+(?:ال)?شديده|حساسيه.*(?:انتفاخ|تورم)\s+(?:في\s+)?(?:ال)?وجه|(?:انتفاخ|تورم)\s+(?:في\s+)?(?:ال)?وجه|(?:انتفاخ|تورم)\s+(?:في\s+)?(?:ال)?لسان|(?:انتفاخ|تورم)\s+(?:في\s+)?(?:ال)?حلق|صعوبه بلع مع تورم",
    "تسمم/جرعة زائدة": r"تسمم|جرعه زائده|جرعه زايده|اخد جرعه كبيره|ابتلع دواء|شرب منظف",
    "حمل/طفل عالي الخطورة": r"طفل حديث الولاده.*تعب|رضيع.*صعوبه تنفس",
}

MEDICAL = re.compile(
    r"اعراض|مرض|تشخيص|علاج|جرعه|دواء|ادويه|الم|وجع|حراره|حمى|كحه|كحة|سعال|صداع|مغص|اسهال|قيء|قئ|"
    r"حساسيه|ضغط|سكر|حامل|حمل|طفل|رضيع|التهاب|عدوى|مضاد حيوي|antibiotic|symptom|diagnos|dose|pain|fever"
)

DRUG_REQUEST = re.compile(r"دواء|ادويه|علاج|جرعه|بديل|بديل ل|تداخل|تعارض|ماده فعاله|active ingredient|drug")


def red_flag(text: str) -> str | None:
    for label, pattern in RED_FLAG_GROUPS.items():
        if re.search(pattern, text):
            return label
    return None


def stock_response(db: Session) -> ChatResponse:
    items = (
        db.query(Product)
        .filter(Product.quantity <= Product.reorder_level, Product.active == True)
        .order_by(Product.quantity.asc())
        .all()
    )
    if not items:
        return ChatResponse(reply="لا توجد منتجات عند أو تحت حد إعادة الطلب حاليًا.", intent="stock_status")
    return ChatResponse(
        reply=f"وجدت {len(items)} منتجًا عند أو تحت حد إعادة الطلب. راجع القائمة قبل تنفيذ طلب الشراء.",
        intent="stock_alert",
        matched_products=[product_dict(p) for p in items[:15]],
        suggestions=["فتح المخزون", "تقرير النواقص", "ابحث عن دواء"],
    )


def search_products(db: Session, query: str) -> list[Product]:
    # Try the full phrase first, then individual useful tokens for Arabic questions.
    terms = [query]
    tokens = [t for t in re.split(r"\s+", query) if len(t) >= 2]
    if tokens and len(tokens) <= 8:
        terms.extend(tokens[:5])

    seen = set()
    result: list[Product] = []
    for term in terms:
        rows = (
            db.query(Product)
            .filter(
                or_(
                    Product.name.ilike(f"%{term}%"),
                    Product.description.ilike(f"%{term}%"),
                    Product.manufacturer.ilike(f"%{term}%"),
                    Product.barcode.ilike(f"%{term}%"),
                ),
                Product.active == True,
            )
            .limit(15)
            .all()
        )
        for row in rows:
            if row.id not in seen:
                seen.add(row.id)
                result.append(row)
    return result[:15]


def extract_product_query(text: str) -> str:
    """Remove conversational filler while preserving the requested product name."""
    stop_words = {
        "عن", "سعر", "بكام", "كم", "هل", "يوجد", "في", "عند", "عندكم", "عندي",
        "متوفر", "موجود", "دواء", "ادويه", "اسمه", "اسم", "باسم", "ابحث", "البحث",
        "عايز", "عاوزه", "محتاج", "محتاجه", "لو", "سمحت", "من", "فضلك", "ايه",
        "اي", "هو", "هي", "الدواء", "معين", "باركود", "لوسمحت"
    }
    cleaned = re.sub(r"[؟?،,.:;!\"'()\[\]{}]", " ", normalize_ar(text))
    words = [word for word in cleaned.split() if word not in stop_words]
    return " ".join(words).strip()


def safe_medical_reply(text: str) -> ChatResponse:
    if re.search(r"جرعه|جرعة|dose|اخد ايه|اخذ ايه|اديني علاج|وصفه|روشته", text):
        return ChatResponse(
            reply=(
                "أقدر أشرح معلومات عامة عن الدواء، لكن لا أستطيع تحديد جرعة أو وصف علاج لشخص بعينه "
                "من خلال الشات فقط. الجرعة تعتمد على العمر والوزن والحمل ووظائف الكلى والكبد والأدوية الأخرى. "
                "اذكر اسم الدواء إن أردت البحث عن بياناته في النظام، أو راجع الصيدلي/الطبيب لتحديد الجرعة المناسبة."
            ),
            intent="dose_safety",
            safety_level="clinical_caution",
            suggestions=["البحث عن اسم الدواء", "التحدث مع الصيدلي المسؤول"],
        )

    if re.search(r"تشخيص|ايه المرض|ما هو مرضي|عندي ايه|انا عندي", text):
        return ChatResponse(
            reply=(
                "لا يمكنني تأكيد تشخيص من خلال المحادثة وحدها. أستطيع مساعدتك في فرز درجة الخطورة، "
                "وتجميع معلومات مفيدة للطبيب، وشرح معلومات عامة عن الأدوية بعد معرفة اسمها. "
                "إذا ظهرت صعوبة تنفس، ألم صدر شديد، فقدان وعي، تشنج، نزيف شديد أو تورم باللسان/الحلق فتوجّه للطوارئ فورًا."
            ),
            intent="diagnosis_safety",
            safety_level="clinical_caution",
            suggestions=["ما علامات الخطر؟", "البحث عن دواء"],
        )

    return ChatResponse(
        reply=(
            "أستطيع مساعدتك بأمان في: البحث عن دواء داخل الصيدلية، معرفة التوافر والسعر، "
            "معلومات دوائية عامة، أو فرز علامات الخطر. لا أستبدل الفحص الطبي ولا أصف علاجًا شخصيًا."
        ),
        intent="medical_safety",
        safety_level="clinical_caution",
        suggestions=["هل يوجد دواء معين؟", "ما الأدوية الناقصة؟", "متى أذهب للطوارئ؟"],
    )


@router.get("/health")
def chatbot_health():
    return {"status": "ok", "service": "clinical-pharmacy-assistant", "version": "2.1.0"}


@router.post("/query", response_model=ChatResponse)
def chatbot_query(data: ChatMessage, db: Session = Depends(get_db), user=Depends(current_user)):
    raw = data.message.strip()
    text = normalize_ar(raw)

    # Educational questions about severe allergy should not be escalated solely because
    # they contain the phrase "severe allergy". Actual danger signs still take priority.
    allergy_education = (
        re.search(r"حساسيه (?:ال)?شديده|حساسيه مفرطه|حساسيه مهدده للحياه", text)
        and re.search(r"اعراض|علامات|ما هي|ايه|ما", text)
        and not re.search(r"ضيق نفس|صعوبه تنفس|اختناق|تورم الوجه|تورم اللسان|تورم الحلق|صعوبه بلع|دوخه شديده|اغماء", text)
    )
    if allergy_education:
        return ChatResponse(
            reply=(
                "قد تشمل علامات الحساسية الشديدة صعوبة التنفس أو الصفير، تورم اللسان أو الحلق، "
                "صعوبة البلع، دوخة شديدة أو إغماء، أو تدهورًا سريعًا بعد التعرض لمسبب الحساسية. "
                "إذا كان أيٌّ من هذه الأعراض يحدث الآن، اتصل بالطوارئ فورًا ولا تنتظر ردًا عبر الدردشة. "
                "هذه معلومات عامة وليست تشخيصًا."
            ),
            intent="allergy_guidance",
            safety_level="clinical_caution",
            suggestions=["علامات الخطر الأخرى", "التحدث مع الصيدلي المسؤول"],
        )

    # Self-harm language needs a supportive response, never the generic fallback.
    self_harm = re.search(
        r"عايز\s+(?:انتحر|اموت)|عاوزه\s+(?:انتحر|اموت)|اريد\s+الانتحار|نفسي\s+(?:اموت|انتحر)|هنتحر|افكر\s+في\s+الانتحار|افكر\s+انهي\s+حياتي|اذي\s+نفسي|ايذي\s+نفسي|اؤذي\s+نفسي|انهاء\s+حياتي|مش\s+عايز\s+اعيش|مش\s+عاوزه\s+اعيش",
        text,
    )
    if self_harm:
        return ChatResponse(
            reply=(
                "أنا آسف إنك بتمر بالألم ده، وشكرًا إنك قلتلي. سلامتك أهم حاجة دلوقتي. "
                "لو في احتمال إنك تؤذي نفسك الآن، ابعد عن أي شيء ممكن تستخدمه لإيذاء نفسك، "
                "وخليك مع شخص تثق به واطلب منه يساعدك فورًا، أو اتصل بالطوارئ المحلية/اذهب لأقرب طوارئ. "
                "هل أنت في خطر مباشر أو بدأت تؤذي نفسك بالفعل؟"
            ),
            intent="self_harm_support",
            safety_level="urgent_support",
            suggestions=["أنا في خطر الآن", "أحتاج أتحدث مع شخص موثوق", "أريد مساعدة فورية"],
        )

    flag = red_flag(text)
    if flag:
        return ChatResponse(
            reply=(
                f"وجدت علامة خطر محتملة ({flag}). لا تحاول الاعتماد على الشات بوت للتشخيص أو العلاج. "
                "إذا كانت الأعراض موجودة الآن أو شديدة/تتفاقم، اطلب الطوارئ أو توجّه لأقرب قسم طوارئ فورًا. "
                "في حالة الاشتباه في تسمم أو جرعة زائدة، لا تحاول إحداث القيء واتصل بخدمة الطوارئ/مركز السموم المحلي."
            ),
            intent="emergency_triage",
            safety_level="emergency",
            suggestions=["التوجه للطوارئ", "التحدث مع طبيب/صيدلي فورًا"],
        )

    if re.search(r"^(مرحبا|اهلا|اهلا وسهلا|سلام|السلام عليكم|hello|hi)\b", text):
        return ChatResponse(
            reply=(
                "أهلًا بك 👋 أنا المساعد السريري والصيدلي في PharmaSys. أقدر أبحث في مخزون الصيدلية، "
                "أشرح معلومات دوائية عامة، وأحدد علامات الخطر التي تستدعي مختصًا. لا أستبدل الطبيب ولا أصف جرعات شخصية."
            ),
            intent="greeting",
            suggestions=["هل يوجد دواء معين؟", "ما الأدوية الناقصة؟", "متى أذهب للطوارئ؟"],
        )

    if any(k in text for k in ["نقص", "ناقص", "منتهي", "خلص", "out of stock", "low stock", "مخزون حرج"]):
        return stock_response(db)

    if re.search(r"متى.*طوارئ|علامات الخطر|امتى.*طوارئ|خطر|emergency", text):
        return ChatResponse(
            reply=(
                "من أهم علامات الخطر: صعوبة/توقف التنفس، ألم صدر شديد، فقدان الوعي، تشنج، ضعف مفاجئ أو اضطراب شديد بالكلام، "
                "نزيف لا يتوقف، أو تورم اللسان/الحلق مع صعوبة التنفس. عند وجود أي منها اطلب الطوارئ فورًا."
            ),
            intent="emergency_guidance",
            safety_level="clinical_caution",
            suggestions=["البحث عن دواء", "التحدث مع الصيدلي المسؤول"],
        )

    # Product/medicine lookup. Keep this before generic medical handling so a query such as
    # "هل عندكم بانادول للصداع؟" still gets a real inventory answer.
    if DRUG_REQUEST.search(text) or "اسمه" in text or any(k in text for k in ["متوفر", "موجود", "سعر", "بكام", "باركود"]):
        cleaned = extract_product_query(text)
        if cleaned:
            products = search_products(db, cleaned)
            if products:
                lines = ["وجدت هذه المنتجات في بيانات الصيدلية:"]
                for p in products[:7]:
                    status = f"متوفر ({p.quantity} {p.unit})" if p.quantity > 0 else "غير متوفر"
                    expiry = f" — الصلاحية {p.expiry_date.isoformat()}" if p.expiry_date else ""
                    lines.append(f"• {p.name}: {p.selling_price:g} — {status}{expiry}")
                if MEDICAL.search(text):
                    lines.append("\nالتوافر والسعر لا يعنيان أن الدواء مناسب للحالة أو أن الجرعة آمنة؛ القرار العلاجي لمختص.")
                return ChatResponse(
                    reply="\n".join(lines),
                    intent="product_search",
                    safety_level="clinical_caution" if MEDICAL.search(text) else "normal",
                    matched_products=[product_dict(p) for p in products],
                )
            # A clear inventory lookup with no match should say so, not fall through
            # to the generic medical-safety response.
            if re.search(r"دواء|ادويه|اسمه|باسم|متوفر|موجود|سعر|بكام|باركود", text):
                requested = cleaned or raw
                return ChatResponse(
                    reply=f"لم أجد منتجًا مطابقًا لـ «{requested}» في قاعدة الصيدلية الحالية. تأكد من كتابة الاسم كما على العبوة أو المادة الفعالة.",
                    intent="product_not_found",
                    safety_level="normal",
                    suggestions=["إعادة كتابة اسم الدواء", "البحث بالباركود"],
                )

    if MEDICAL.search(text):
        return safe_medical_reply(text)

    # A plain medicine/product name (without words such as "دواء") should still be searchable.
    if len(text) >= 2:
        products = search_products(db, extract_product_query(text))
        if products:
            return ChatResponse(
                reply="وجدت منتجات مطابقة في الصيدلية. راجع التوافر والسعر، وإذا كان سؤالك عن الاستخدام أو الجرعة فاستشر مختصًا.",
                intent="product_search",
                matched_products=[product_dict(p) for p in products],
            )

    return ChatResponse(
        reply=(
            "لم أفهم السؤال بالكامل. اكتب اسم الدواء/المادة الفعالة، أو اسأل عن التوافر والسعر، "
            "المخزون الناقص، أو علامات الخطر."
        ),
        intent="fallback",
        suggestions=["هل يوجد دواء معين؟", "الأدوية الناقصة", "متى أذهب للطوارئ؟"],
    )
