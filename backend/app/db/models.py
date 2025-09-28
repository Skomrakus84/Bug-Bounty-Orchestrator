from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.db.base import Base
import datetime

class Target(Base):
	__tablename__ = "targets"
	id = Column(Integer, primary_key=True, index=True)
	url = Column(String, unique=True, index=True, nullable=False)
	created_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
	scans = relationship("Scan", back_populates="target")

class Scan(Base):
	__tablename__ = "scans"
	id = Column(Integer, primary_key=True, index=True)
	target_id = Column(Integer, ForeignKey("targets.id"), index=True)
	domain = Column(String, index=True)
	status = Column(String, default="pending", index=True)
	started_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
	completed_at = Column(DateTime, nullable=True, index=True)
	target = relationship("Target", back_populates="scans")
	vulnerabilities = relationship("Vulnerability", back_populates="scan")

class Vulnerability(Base):
	__tablename__ = "vulnerabilities"
	id = Column(Integer, primary_key=True, index=True)
	scan_id = Column(Integer, ForeignKey("scans.id"))
	name = Column(String)
	severity = Column(String)
	description = Column(Text)
	url = Column(String)
	scan = relationship("Scan", back_populates="vulnerabilities")
