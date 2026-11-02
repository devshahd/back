from datetime import date, datetime
from pydantic import BaseModel, Field, ConfigDict, model_validator, AliasChoices
from typing import Literal

class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    full_name: str = Field(min_length=2, max_length=160)
    password: str = Field(min_length=8)
    role: str = "pharmacist"

class LoginInput(BaseModel):
    username: str
    password: str

class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    session_id: str

class CategoryCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    description: str | None = None
class CategoryOut(CategoryCreate):
    id: int
    model_config = ConfigDict(from_attributes=True)

class ProductCreate(BaseModel):
    name: str = Field(min_length=2, max_length=180)
    barcode: str | None = None
    description: str | None = None
    manufacturer: str | None = None
    unit: str = "piece"
    purchase_price: float = Field(ge=0)
    selling_price: float = Field(ge=0)
    quantity: int = Field(default=0, ge=0)
    reorder_level: int = Field(default=5, ge=0)
    expiry_date: date | None = None
    category_id: int | None = None

class ProductUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=180)
    barcode: str | None = None
    description: str | None = None
    manufacturer: str | None = None
    unit: str | None = Field(default=None, min_length=1, max_length=30)
    purchase_price: float | None = Field(default=None, ge=0)
    selling_price: float | None = Field(default=None, ge=0)
    reorder_level: int | None = Field(default=None, ge=0)
    expiry_date: date | None = None
    category_id: int | None = None
    active: bool | None = None

    @model_validator(mode="before")
    @classmethod
    def reject_null_for_required_columns(cls, value):
        if isinstance(value, dict):
            required = {"name", "unit", "purchase_price", "selling_price", "reorder_level", "active"}
            invalid = sorted(key for key in required if key in value and value[key] is None)
            if invalid:
                raise ValueError("These fields cannot be null: " + ", ".join(invalid))
        return value

class ProductOut(ProductCreate):
    id: int
    active: bool
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class StockChange(BaseModel):
    quantity: int = Field(gt=0)
    movement_type: str = "in"
    note: str | None = None

class StockBatchItem(BaseModel):
    product_id: int = Field(gt=0)
    quantity: int = Field(gt=0)
    movement_type: str = "in"
    note: str | None = Field(default=None, max_length=240)

class StockBatchChange(BaseModel):
    operation_id: str = Field(min_length=1, max_length=160)
    movements: list[StockBatchItem] = Field(min_length=1, max_length=100)

class SaleLineInput(BaseModel):
    product_id: int = Field(gt=0)
    quantity: int = Field(gt=0)
    # Optional for backward compatibility; when supplied, prevents checkout using stale local prices.
    expected_unit_price: float | None = Field(default=None, ge=0, le=100000000)
class SaleCreate(BaseModel):
    client_reference: str | None = Field(default=None, max_length=160)
    branch_id: int | None = Field(default=None, gt=0)
    items: list[SaleLineInput] = Field(min_length=1)
    discount: float = Field(default=0, ge=0)
    payment_method: Literal["cash", "card"] = "cash"
    customer_name: str | None = None
class SaleReturnLineInput(BaseModel):
    product_id: int = Field(gt=0)
    quantity: int = Field(gt=0)
class SaleReturnCreate(BaseModel):
    operation_id: str = Field(min_length=1, max_length=160)
    items: list[SaleReturnLineInput] = Field(default_factory=list, max_length=100)
    reason: str = Field(min_length=1, max_length=120)
    notes: str | None = Field(default=None, max_length=1000)
class SaleCancelCreate(BaseModel):
    operation_id: str = Field(min_length=1, max_length=160)
    reason: str = Field(min_length=1, max_length=120)
    notes: str | None = Field(default=None, max_length=1000)
class SaleItemOut(BaseModel):
    product_id: int
    product_name: str
    quantity: int
    returned_quantity: int = 0
    unit_price: float
    line_total: float
    model_config = ConfigDict(from_attributes=True)
class SaleOut(BaseModel):
    id: int
    branch_id: int | None = None
    invoice_number: str
    subtotal: float
    discount: float
    total: float
    payment_method: str
    customer_name: str | None
    created_at: datetime
    status: str = "completed"
    items: list[SaleItemOut]
    model_config = ConfigDict(from_attributes=True)


class PurchaseLineInput(BaseModel):
    product_id: int = Field(gt=0, validation_alias=AliasChoices("product_id", "productId"))
    quantity: int = Field(gt=0, le=100000)
    purchase_price: float = Field(ge=0, le=100000000, validation_alias=AliasChoices("purchase_price", "purchasePrice"))

class PurchaseCreate(BaseModel):
    purchase_number: str = Field(min_length=3, max_length=60, validation_alias=AliasChoices("purchase_number", "purchaseNumber"))
    supplier_id: str = Field(min_length=1, max_length=160, validation_alias=AliasChoices("supplier_id", "supplierId"))
    supplier_name: str = Field(min_length=2, max_length=180, validation_alias=AliasChoices("supplier_name", "supplierName"))
    items: list[PurchaseLineInput] = Field(min_length=1, max_length=100)
    discount: float = Field(default=0, ge=0, le=100000000)

class DeliveryOrderItem(BaseModel):
    product_id: int = Field(gt=0, validation_alias=AliasChoices("product_id", "productId", "id"))
    quantity: int = Field(gt=0, validation_alias=AliasChoices("quantity", "qty"))

class DeliveryOrderCreate(BaseModel):
    customer_name: str = Field(min_length=2, max_length=160)
    phone: str = Field(min_length=5, max_length=40)
    address: str = Field(min_length=3)
    # Prices/totals are always recalculated server-side from the invoice or product records.
    items: list[DeliveryOrderItem] = Field(default_factory=list, max_length=100)
    delivery_fee: float = Field(default=0, ge=0, le=100000)
    cod: bool = True
    driver_id: int | None = Field(default=None, gt=0)
    notes: str | None = Field(default=None, max_length=1000)
    sale_id: int | None = Field(default=None, gt=0)



class BranchCreate(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    code: str = Field(min_length=2, max_length=40)
    address: str | None = None

class BranchOut(BranchCreate):
    id: int
    active: bool
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class TransferItemCreate(BaseModel):
    product_id: int
    quantity: int = Field(gt=0)

class StockTransferCreate(BaseModel):
    from_branch_id: int
    to_branch_id: int
    items: list[TransferItemCreate] = Field(min_length=1)
    note: str | None = None

class StockTransferItemOut(BaseModel):
    product_id: int
    quantity: int
    product_name: str | None = None

class StockTransferOut(BaseModel):
    id: int
    transfer_number: str
    from_branch_id: int
    from_branch_name: str
    to_branch_id: int
    to_branch_name: str
    status: str
    requested_by: int | None
    approved_by: int | None
    note: str | None
    created_at: datetime
    completed_at: datetime | None
    items: list[StockTransferItemOut]


class SupplierPerformanceCreate(BaseModel):
    quality: float = Field(ge=1, le=5)
    delivery: float = Field(ge=1, le=5)
    price: float = Field(ge=1, le=5)
    service: float = Field(ge=1, le=5)
    compliance: float = Field(ge=1, le=5)
    notes: str | None = None

class SupplierPerformanceOut(SupplierPerformanceCreate):
    id: int
    supplier_id: str
    overall: float
    rated_by: int | None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class PurchasePriceHistoryOut(BaseModel):
    id: int
    product_id: int
    supplier_id: str | None
    supplier_name: str | None
    purchase_number: str | None
    unit_price: float
    quantity: int
    total_cost: float
    purchased_at: datetime
    model_config = ConfigDict(from_attributes=True)

class DeliveryStatusUpdate(BaseModel):
    status: str
    driver_id: int | None = None

class DeliveryOrderOut(BaseModel):
    id: int
    order_number: str
    customer_name: str
    phone: str
    address: str
    items: list[dict]
    items_total: float
    delivery_fee: float
    total: float
    cod: bool
    status: str
    driver_id: int | None
    driver_name: str | None = None
    sale_id: int | None = None
    notes: str | None
    created_at: datetime
    updated_at: datetime
