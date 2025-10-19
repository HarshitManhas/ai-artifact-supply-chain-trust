#!/usr/bin/env python3
"""
AI Artifact Supply Chain Trust Dashboard Backend

FastAPI backend providing REST APIs for SBOM management, visualization,
and artifact verification status.
"""

import os
import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import uvicorn
from neo4j import GraphDatabase
import redis

# Add src to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from artifact_creation import SBOMGenerator, SBOMEntry
from signing import ArtifactSigner, SignedSBOM
from verification import ArtifactVerifier
from sbom_storage import SBOMRegistry

# Pydantic models for API requests/responses
class SBOMRequest(BaseModel):
    artifact_path: str
    include_dependencies: bool = True
    additional_metadata: Optional[Dict[str, Any]] = None

class SigningRequest(BaseModel):
    sbom_id: str
    signer_info: Optional[Dict[str, Any]] = None

class VerificationRequest(BaseModel):
    artifact_path: str
    sbom_id: Optional[str] = None

class ArtifactStats(BaseModel):
    total_artifacts: int
    signed_artifacts: int
    verified_artifacts: int
    failed_verifications: int

class SBOMResponse(BaseModel):
    sbom_id: str
    artifact_path: str
    artifact_hash: str
    metadata: Dict[str, Any]
    dependencies: List[Dict[str, Any]]
    created_at: str
    is_signed: bool = False
    is_verified: bool = False

# Initialize FastAPI app
app = FastAPI(
    title="AI Artifact Supply Chain Trust Dashboard",
    description="REST API for managing AI artifact SBOMs, signatures, and verification",
    version="1.0.0"
)

# CORS middleware for frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://frontend:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global dependencies
neo4j_driver = None
redis_client = None
sbom_generator = SBOMGenerator()
sbom_registry = None

@app.on_event("startup")
async def startup_event():
    """Initialize database connections and services."""
    global neo4j_driver, redis_client, sbom_registry
    
    # Neo4j connection
    neo4j_uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    neo4j_user = os.getenv("NEO4J_USER", "neo4j")
    neo4j_password = os.getenv("NEO4J_PASSWORD", "ai-trust-password")
    
    try:
        neo4j_driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        # Test connection
        with neo4j_driver.session() as session:
            session.run("RETURN 1")
        print("✅ Connected to Neo4j")
    except Exception as e:
        print(f"❌ Failed to connect to Neo4j: {e}")
    
    # Redis connection (optional)
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    try:
        redis_client = redis.from_url(redis_url)
        redis_client.ping()
        print("✅ Connected to Redis")
    except Exception as e:
        print(f"⚠️ Redis not available (optional): {e}")
        redis_client = None
    
    # Initialize SBOM Registry
    if neo4j_driver:
        sbom_registry = SBOMRegistry(neo4j_driver)

@app.on_event("shutdown")
async def shutdown_event():
    """Close database connections."""
    if neo4j_driver:
        neo4j_driver.close()
    if redis_client:
        redis_client.close()

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "services": {
            "neo4j": neo4j_driver is not None,
            "redis": redis_client is not None
        }
    }

# SBOM Management Endpoints
@app.post("/api/sboms/create", response_model=SBOMResponse)
async def create_sbom(request: SBOMRequest):
    """Create a new SBOM entry for an artifact."""
    try:
        if not os.path.exists(request.artifact_path):
            raise HTTPException(status_code=404, detail="Artifact file not found")
        
        sbom_entry = sbom_generator.create_sbom(
            artifact_path=request.artifact_path,
            include_dependencies=request.include_dependencies,
            additional_metadata=request.additional_metadata
        )
        
        # Store in Neo4j if available
        if sbom_registry:
            await sbom_registry.store_sbom(sbom_entry)
        
        # Cache in Redis
        if redis_client:
            redis_client.setex(
                f"sbom:{sbom_entry.sbom_id}",
                3600,  # 1 hour TTL
                json.dumps(sbom_entry.to_dict())
            )
        
        return SBOMResponse(
            sbom_id=sbom_entry.sbom_id,
            artifact_path=sbom_entry.artifact_path,
            artifact_hash=sbom_entry.artifact_hash,
            metadata=sbom_entry.metadata,
            dependencies=sbom_entry.dependencies,
            created_at=sbom_entry.created_at
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/sboms/{sbom_id}", response_model=SBOMResponse)
async def get_sbom(sbom_id: str):
    """Retrieve an SBOM entry by ID."""
    try:
        # Try Redis cache first
        if redis_client:
            cached_sbom = redis_client.get(f"sbom:{sbom_id}")
            if cached_sbom:
                data = json.loads(cached_sbom)
                return SBOMResponse(**data)
        
        # Fall back to Neo4j
        if sbom_registry:
            sbom_entry = await sbom_registry.get_sbom(sbom_id)
            if sbom_entry:
                return SBOMResponse(
                    sbom_id=sbom_entry.sbom_id,
                    artifact_path=sbom_entry.artifact_path,
                    artifact_hash=sbom_entry.artifact_hash,
                    metadata=sbom_entry.metadata,
                    dependencies=sbom_entry.dependencies,
                    created_at=sbom_entry.created_at
                )
        
        raise HTTPException(status_code=404, detail="SBOM not found")
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/sboms", response_model=List[SBOMResponse])
async def list_sboms(limit: int = 100, offset: int = 0):
    """List all SBOM entries with pagination."""
    try:
        if not sbom_registry:
            return []
        
        sbom_entries = await sbom_registry.list_sboms(limit=limit, offset=offset)
        return [
            SBOMResponse(
                sbom_id=entry.sbom_id,
                artifact_path=entry.artifact_path,
                artifact_hash=entry.artifact_hash,
                metadata=entry.metadata,
                dependencies=entry.dependencies,
                created_at=entry.created_at
            )
            for entry in sbom_entries
        ]
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Verification Endpoints
@app.post("/api/verify/artifact")
async def verify_artifact(request: VerificationRequest):
    """Verify an artifact against its SBOM."""
    try:
        if not os.path.exists(request.artifact_path):
            raise HTTPException(status_code=404, detail="Artifact file not found")
        
        verifier = ArtifactVerifier()
        
        if request.sbom_id:
            # Verify against specific SBOM
            sbom_entry = None
            if redis_client:
                cached_sbom = redis_client.get(f"sbom:{request.sbom_id}")
                if cached_sbom:
                    data = json.loads(cached_sbom)
                    sbom_entry = SBOMEntry(
                        artifact_path=data['artifact_path'],
                        artifact_hash=data['artifact_hash'],
                        metadata=data['metadata'],
                        dependencies=data.get('dependencies', [])
                    )
            
            if not sbom_entry and sbom_registry:
                sbom_entry = await sbom_registry.get_sbom(request.sbom_id)
            
            if not sbom_entry:
                raise HTTPException(status_code=404, detail="SBOM not found")
            
            is_valid = verifier.verify_artifact(request.artifact_path, sbom_entry)
        else:
            # Find and verify against any matching SBOM
            is_valid = await verifier.verify_artifact_auto(request.artifact_path)
        
        return {
            "artifact_path": request.artifact_path,
            "is_valid": is_valid,
            "verified_at": datetime.now(timezone.utc).isoformat(),
            "sbom_id": request.sbom_id
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Statistics and Dashboard Data
@app.get("/api/stats", response_model=ArtifactStats)
async def get_stats():
    """Get dashboard statistics."""
    try:
        if not sbom_registry:
            return ArtifactStats(
                total_artifacts=0,
                signed_artifacts=0,
                verified_artifacts=0,
                failed_verifications=0
            )
        
        stats = await sbom_registry.get_statistics()
        return ArtifactStats(**stats)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/artifacts/recent")
async def get_recent_artifacts(limit: int = 10):
    """Get recently added artifacts."""
    try:
        if not sbom_registry:
            return []
        
        recent = await sbom_registry.get_recent_artifacts(limit)
        return recent
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# File Upload Endpoint
@app.post("/api/upload/artifact")
async def upload_artifact(file: UploadFile = File(...), metadata: str = None):
    """Upload an artifact file and create SBOM."""
    try:
        # Save uploaded file
        upload_dir = Path("uploads/artifacts")
        upload_dir.mkdir(parents=True, exist_ok=True)
        
        file_path = upload_dir / file.filename
        with open(file_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)
        
        # Parse metadata if provided
        additional_metadata = {}
        if metadata:
            additional_metadata = json.loads(metadata)
        
        # Create SBOM
        sbom_entry = sbom_generator.create_sbom(
            artifact_path=str(file_path),
            additional_metadata=additional_metadata
        )
        
        # Store in registry
        if sbom_registry:
            await sbom_registry.store_sbom(sbom_entry)
        
        return {
            "message": "Artifact uploaded and SBOM created",
            "sbom_id": sbom_entry.sbom_id,
            "artifact_path": str(file_path),
            "file_size": len(content),
            "artifact_hash": sbom_entry.artifact_hash
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Development server
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )