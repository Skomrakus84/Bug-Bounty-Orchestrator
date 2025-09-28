from fastapi import FastAPI
from app.api.v1.endpoints.scans import router as scans_router
from app.api.v1.endpoints.targets import router as targets_router
import logging
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

logging.basicConfig(level=logging.INFO)

app = FastAPI()
app.include_router(scans_router, prefix="/api/v1", tags=["scans"])
app.include_router(targets_router, prefix="/api/v1", tags=["targets"])