from pydantic import BaseModel, validator
from typing import Optional, List
import datetime
import re

class VulnerabilityBase(BaseModel):
    name: str
    severity: str
    description: Optional[str] = None
    url: Optional[str] = None

class VulnerabilityCreate(VulnerabilityBase):
    pass

class Vulnerability(VulnerabilityBase):
    id: int
    scan_id: int
    class Config:
        from_attributes = True

class TargetBase(BaseModel):
    domain_name: str
    class Config:
        from_attributes = True
        fields = {"domain_name": "url"}

    @validator('domain_name')
    def validate_domain_name(cls, v):
        if not v or not isinstance(v, str):
            raise ValueError('Domain name must be a non-empty string')
        
        # Remove protocol if present
        v = re.sub(r'^https?://', '', v.lower().strip())
        
        # Basic domain validation regex
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if not re.match(domain_pattern, v):
            raise ValueError('Invalid domain name format')
        
        # Check length
        if len(v) > 253:
            raise ValueError('Domain name too long (max 253 characters)')
        
        return v

class TargetCreate(TargetBase):
    pass

class Target(TargetBase):
    id: int
    created_at: datetime.datetime
    scans: List["Scan"] = []
    class Config:
        from_attributes = True
        fields = {"domain_name": "url"}

class ScanBase(BaseModel):
    status: Optional[str] = "pending"

class ScanCreate(ScanBase):
    target_id: int

class ScanCreateWithDomain(BaseModel):
    domain: str
    status: Optional[str] = "pending"

class Scan(ScanBase):
    id: int
    domain: str
    started_at: datetime.datetime
    completed_at: Optional[datetime.datetime]
    vulnerabilities: List[Vulnerability] = []
    class Config:
        from_attributes = True