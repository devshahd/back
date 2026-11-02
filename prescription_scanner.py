import re
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from sqlalchemy.orm import Session
from typing import List
try:
    from .app.database import get_db
    from .app.models import Product
    from .app.security import current_user
except ImportError:
    from app.database import get_db
    from app.models import Product
    from app.security import current_user

router = APIRouter(prefix="/scanner", tags=["Prescription Scanner"])
MAX_PRESCRIPTION_BYTES = 10 * 1024 * 1024

def extract_text_from_image(image_bytes: bytes) -> str:
    """Preprocess image and extract text using Tesseract OCR."""
    try:
        import cv2
        import numpy as np
        import pytesseract
    except ImportError as exc:
        raise HTTPException(status_code=503, detail="Prescription OCR dependencies are not installed") from exc
    if not image_bytes:
        raise HTTPException(status_code=400, detail="Uploaded image is empty")
    if not pytesseract.pytesseract.tesseract_cmd:
        raise HTTPException(status_code=503, detail="Tesseract OCR is not configured on this computer")
    try:
        # Confirm the external OCR executable exists before doing image processing.
        pytesseract.get_tesseract_version()
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Tesseract OCR is not installed or is not on PATH. Install Tesseract and add its installation folder to PATH.") from exc

    nparr = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    if img is None:
        raise HTTPException(status_code=400, detail="Invalid image file")

    # Convert to grayscale and threshold for clearer text extraction.
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    processed = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]
    try:
        return pytesseract.image_to_string(processed, lang="eng+ara")
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Tesseract OCR could not initialize Arabic/English recognition. Install the ara and eng language data, then restart PharmaSys.",
        ) from exc

@router.post("/scan-prescription", tags=["Prescription Scanner"])
async def scan_prescription(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user=Depends(current_user)
):
    """
    Upload a prescription image, scan text via OCR, and match detected medicines with DB inventory.
    """
    if not (file.content_type or "").lower().startswith("image/"):
        raise HTTPException(status_code=400, detail="Uploaded file must be an image")

    contents = await file.read(MAX_PRESCRIPTION_BYTES + 1)
    if len(contents) > MAX_PRESCRIPTION_BYTES:
        raise HTTPException(status_code=413, detail="Prescription image must be 10 MiB or smaller")
    if not contents:
        raise HTTPException(status_code=400, detail="Uploaded image is empty")
    raw_text = extract_text_from_image(contents)
    
    # Simple word tokenization to match product names in database
    words = [w.strip() for w in re.split(r'[\s,\n]+', raw_text) if len(w.strip()) > 2]
    matched_products = []
    
    all_products = db.query(Product).filter(Product.active == True).all()
    for prod in all_products:
        prod_name_lower = prod.name.lower()
        if any(w.lower() in prod_name_lower or prod_name_lower in w.lower() for w in words):
            matched_products.append({
                "id": prod.id,
                "name": prod.name,
                "price": prod.selling_price,
                "quantity": prod.quantity,
                "barcode": prod.barcode
            })
            
    return {
        "filename": file.filename,
        "extracted_text": raw_text,
        "detected_medicines_count": len(matched_products),
        "matched_products": matched_products
    }
