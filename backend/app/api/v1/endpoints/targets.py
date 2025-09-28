from fastapi import APIRouter, Depends, HTTPException, Header, Request
from sqlalchemy.orm import Session
from app.db.database import SessionLocal
from app.db.models import Target
from app.schemas.schemas import Target as TargetSchema, TargetCreate
import time
from collections import defaultdict

router = APIRouter()

# Simple in-memory rate limiter
rate_limit_store = defaultdict(list)
RATE_LIMIT_REQUESTS = 100  # requests per window
RATE_LIMIT_WINDOW = 60  # seconds

def check_rate_limit(request: Request):
    client_ip = request.client.host
    current_time = time.time()
    
    # Clean old requests
    rate_limit_store[client_ip] = [
        timestamp for timestamp in rate_limit_store[client_ip] 
        if current_time - timestamp < RATE_LIMIT_WINDOW
    ]
    
    # Check if under limit
    if len(rate_limit_store[client_ip]) >= RATE_LIMIT_REQUESTS:
        raise HTTPException(
            status_code=429, 
            detail=f"Rate limit exceeded. Maximum {RATE_LIMIT_REQUESTS} requests per {RATE_LIMIT_WINDOW} seconds."
        )
    
    # Add current request
    rate_limit_store[client_ip].append(current_time)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_api_key(x_api_key: str = Header(...)):
    import os
    expected = os.environ.get("API_KEY", "testkey")
    if x_api_key != expected:
        raise HTTPException(status_code=401, detail="Invalid API Key")

@router.post("/targets/", response_model=TargetSchema, dependencies=[Depends(verify_api_key), Depends(check_rate_limit)])
def create_target(target: TargetCreate, db: Session = Depends(get_db)):
    # Sprawdź czy domena już istnieje
    existing = db.query(Target).filter_by(url=target.domain_name).first()
    if existing:
        raise HTTPException(status_code=409, detail="Target with this domain already exists.")
    db_target = Target(url=target.domain_name)
    db.add(db_target)
    db.commit()
    db.refresh(db_target)
    return TargetSchema(
        id=db_target.id,
        domain_name=db_target.url,
        created_at=db_target.created_at,
        scans=[]
    )

@router.get("/targets/", dependencies=[Depends(verify_api_key), Depends(check_rate_limit)])
def read_targets(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    targets = db.query(Target).offset(skip).limit(limit).all()
    result = []
    for t in targets:
        result.append({
            "id": t.id,
            "domain_name": t.url,
            "created_at": t.created_at.isoformat(),
            "scans": []
        })
    return result