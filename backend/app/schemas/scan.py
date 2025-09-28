# Pydantic schemas for scan objects
from pydantic import BaseModel

from typing import List, Optional

class Service(BaseModel):
	port: int
	service_name: Optional[str]

class Scan(BaseModel):
	id: int
	name: str
	status: str
	services: List[Service] = []