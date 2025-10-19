"""
SBOM Registry Module

Provides a comprehensive SBOM registry with REST API endpoints,
search capabilities, and integration with various storage backends.
"""

import os
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Union
from pathlib import Path

# Optional FastAPI import
try:
    from fastapi import FastAPI, HTTPException, Query, Depends
    from fastapi.responses import JSONResponse
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

from .storage_backend import StorageBackend, LocalStorageBackend, Neo4jStorageBackend


class SBOMRegistry:
    """SBOM Registry with storage backend abstraction."""
    
    def __init__(self, storage_backend_or_driver=None):
        # Support both storage backend and direct Neo4j driver
        if hasattr(storage_backend_or_driver, 'session'):
            # It's a Neo4j driver
            self.neo4j_driver = storage_backend_or_driver
            self.storage_backend = None
            self._initialize_neo4j_schema()
        else:
            # It's a storage backend
            self.storage_backend = storage_backend_or_driver
            self.neo4j_driver = None
            
        self.stats = {
            'total_sboms': 0,
            'total_artifacts': 0,
            'registry_created': datetime.now(timezone.utc).isoformat(),
            'last_updated': datetime.now(timezone.utc).isoformat()
        }
    
    def register_sbom(self, sbom_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Register a new SBOM in the registry.
        
        Args:
            sbom_data: SBOM data to register
            
        Returns:
            Registration result with SBOM ID
        """
        try:
            # Validate SBOM data
            validation_result = self._validate_sbom_data(sbom_data)
            if not validation_result['is_valid']:
                return {
                    'success': False,
                    'error': validation_result['error'],
                    'sbom_id': None
                }
            
            # Store SBOM
            sbom_id = self.storage_backend.store_sbom(sbom_data)
            
            # Update stats
            self._update_stats()
            
            return {
                'success': True,
                'sbom_id': sbom_id,
                'message': 'SBOM registered successfully'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'sbom_id': None
            }
    
    def get_sbom(self, sbom_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve SBOM by ID.
        
        Args:
            sbom_id: SBOM identifier
            
        Returns:
            SBOM data or None if not found
        """
        return self.storage_backend.retrieve_sbom(sbom_id)
    
    def search_sboms(self, 
                    artifact_path: Optional[str] = None,
                    artifact_hash: Optional[str] = None,
                    metadata_key: Optional[str] = None,
                    limit: int = 100) -> List[Dict[str, Any]]:
        """
        Search for SBOMs based on criteria.
        
        Args:
            artifact_path: Filter by artifact path (partial match)
            artifact_hash: Filter by exact artifact hash
            metadata_key: Filter by metadata key presence
            limit: Maximum number of results
            
        Returns:
            List of matching SBOM entries
        """
        query = {}
        
        if artifact_path:
            query['artifact_path'] = artifact_path
        if artifact_hash:
            query['artifact_hash'] = artifact_hash
        if metadata_key:
            query['metadata_key'] = metadata_key
        
        results = self.storage_backend.search_sboms(query)
        return results[:limit]
    
    def list_sboms(self, limit: int = 100, offset: int = 0) -> Dict[str, Any]:
        """
        List SBOMs with pagination.
        
        Args:
            limit: Maximum number of results
            offset: Number of results to skip
            
        Returns:
            Dictionary with SBOMs and pagination info
        """
        sboms = self.storage_backend.list_sboms(limit, offset)
        
        return {
            'sboms': sboms,
            'pagination': {
                'limit': limit,
                'offset': offset,
                'count': len(sboms)
            }
        }
    
    def delete_sbom(self, sbom_id: str) -> Dict[str, Any]:
        """
        Delete SBOM by ID.
        
        Args:
            sbom_id: SBOM identifier
            
        Returns:
            Deletion result
        """
        try:
            success = self.storage_backend.delete_sbom(sbom_id)
            
            if success:
                self._update_stats()
                return {
                    'success': True,
                    'message': f'SBOM {sbom_id} deleted successfully'
                }
            else:
                return {
                    'success': False,
                    'error': f'SBOM {sbom_id} not found or could not be deleted'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_registry_stats(self) -> Dict[str, Any]:
        """
        Get registry statistics.
        
        Returns:
            Dictionary with registry statistics
        """
        self._update_stats()
        return self.stats
    
    def verify_artifact_in_registry(self, artifact_hash: str) -> Dict[str, Any]:
        """
        Verify if an artifact is registered in the SBOM registry.
        
        Args:
            artifact_hash: Hash of the artifact to verify
            
        Returns:
            Verification result
        """
        sboms = self.search_sboms(artifact_hash=artifact_hash)
        
        if sboms:
            return {
                'is_registered': True,
                'sbom_count': len(sboms),
                'sbom_ids': [sbom.get('sbom_id') for sbom in sboms],
                'latest_sbom': max(sboms, key=lambda x: x.get('created_at', ''))
            }
        else:
            return {
                'is_registered': False,
                'sbom_count': 0,
                'sbom_ids': [],
                'latest_sbom': None
            }
    
    def _validate_sbom_data(self, sbom_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate SBOM data structure."""
        required_fields = ['artifact_path', 'artifact_hash']
        
        for field in required_fields:
            if field not in sbom_data:
                return {
                    'is_valid': False,
                    'error': f'Missing required field: {field}'
                }
        
        # Additional validations
        if not sbom_data['artifact_hash'] or len(sbom_data['artifact_hash']) != 64:
            return {
                'is_valid': False,
                'error': 'Invalid artifact_hash format (should be SHA-256)'
            }
        
        return {'is_valid': True, 'error': None}
    
    def _initialize_neo4j_schema(self):
        """Initialize Neo4j schema with constraints and indexes."""
        if not self.neo4j_driver:
            return
            
        try:
            with self.neo4j_driver.session() as session:
                # Create uniqueness constraints
                session.run("""
                    CREATE CONSTRAINT sbom_id_unique IF NOT EXISTS 
                    FOR (s:SBOM) REQUIRE s.sbom_id IS UNIQUE
                """)
                
                session.run("""
                    CREATE CONSTRAINT artifact_hash_unique IF NOT EXISTS 
                    FOR (a:Artifact) REQUIRE a.hash IS UNIQUE
                """)
                
                # Create indexes for performance
                session.run("""
                    CREATE INDEX sbom_created_at IF NOT EXISTS 
                    FOR (s:SBOM) ON (s.created_at)
                """)
        except Exception as e:
            print(f"Warning: Failed to initialize Neo4j schema: {e}")
    
    async def store_sbom(self, sbom_entry):
        """Store SBOM entry using Neo4j driver."""
        if not self.neo4j_driver:
            return False
            
        try:
            import json
            with self.neo4j_driver.session() as session:
                session.run("""
                    MERGE (s:SBOM {sbom_id: $sbom_id})
                    SET s.created_at = $created_at,
                        s.metadata = $metadata
                    MERGE (a:Artifact {hash: $artifact_hash})
                    SET a.path = $artifact_path
                    MERGE (s)-[:DESCRIBES]->(a)
                """, {
                    "sbom_id": sbom_entry.sbom_id,
                    "created_at": sbom_entry.created_at,
                    "metadata": json.dumps(sbom_entry.metadata),
                    "artifact_hash": sbom_entry.artifact_hash,
                    "artifact_path": sbom_entry.artifact_path
                })
            return True
        except Exception as e:
            print(f"Failed to store SBOM: {e}")
            return False
    
    async def get_sbom(self, sbom_id: str):
        """Get SBOM by ID from Neo4j."""
        if not self.neo4j_driver:
            return None
            
        try:
            import json
            with self.neo4j_driver.session() as session:
                result = session.run("""
                    MATCH (s:SBOM {sbom_id: $sbom_id})-[:DESCRIBES]->(a:Artifact)
                    RETURN s.metadata as metadata, a.path as artifact_path, 
                           a.hash as artifact_hash, s.created_at as created_at
                """, {"sbom_id": sbom_id})
                
                record = result.single()
                if record:
                    # Create a mock SBOM entry object
                    class MockSBOMEntry:
                        def __init__(self, **kwargs):
                            for k, v in kwargs.items():
                                setattr(self, k, v)
                    
                    metadata = json.loads(record["metadata"]) if record["metadata"] else {}
                    return MockSBOMEntry(
                        sbom_id=sbom_id,
                        artifact_path=record["artifact_path"],
                        artifact_hash=record["artifact_hash"],
                        metadata=metadata,
                        dependencies=[],
                        created_at=record["created_at"]
                    )
        except Exception as e:
            print(f"Failed to get SBOM: {e}")
        return None
    
    async def list_sboms(self, limit: int = 100, offset: int = 0):
        """List SBOMs from Neo4j."""
        if not self.neo4j_driver:
            return []
            
        try:
            import json
            with self.neo4j_driver.session() as session:
                result = session.run("""
                    MATCH (s:SBOM)-[:DESCRIBES]->(a:Artifact)
                    RETURN s.sbom_id as sbom_id, s.created_at as created_at, 
                           s.metadata as metadata, a.path as artifact_path, 
                           a.hash as artifact_hash
                    ORDER BY s.created_at DESC
                    SKIP $offset LIMIT $limit
                """, {"limit": limit, "offset": offset})
                
                sboms = []
                for record in result:
                    class MockSBOMEntry:
                        def __init__(self, **kwargs):
                            for k, v in kwargs.items():
                                setattr(self, k, v)
                    
                    metadata = json.loads(record["metadata"]) if record["metadata"] else {}
                    sboms.append(MockSBOMEntry(
                        sbom_id=record["sbom_id"],
                        artifact_path=record["artifact_path"],
                        artifact_hash=record["artifact_hash"],
                        metadata=metadata,
                        dependencies=[],
                        created_at=record["created_at"]
                    ))
                return sboms
        except Exception as e:
            print(f"Failed to list SBOMs: {e}")
        return []
    
    async def get_statistics(self):
        """Get statistics from Neo4j."""
        if not self.neo4j_driver:
            return {
                "total_artifacts": 0,
                "signed_artifacts": 0, 
                "verified_artifacts": 0,
                "failed_verifications": 0
            }
            
        try:
            with self.neo4j_driver.session() as session:
                result = session.run("""
                    MATCH (s:SBOM)
                    OPTIONAL MATCH (s)-[:HAS_SIGNATURE]->(sig:Signature)
                    RETURN count(s) as total_artifacts,
                           count(sig) as signed_artifacts
                """)
                
                record = result.single()
                if record:
                    return {
                        "total_artifacts": record["total_artifacts"],
                        "signed_artifacts": record["signed_artifacts"],
                        "verified_artifacts": 0,
                        "failed_verifications": 0
                    }
        except Exception as e:
            print(f"Failed to get statistics: {e}")
            
        return {
            "total_artifacts": 0,
            "signed_artifacts": 0,
            "verified_artifacts": 0,
            "failed_verifications": 0
        }
    
    async def get_recent_artifacts(self, limit: int = 10):
        """Get recent artifacts from Neo4j."""
        if not self.neo4j_driver:
            return []
            
        try:
            with self.neo4j_driver.session() as session:
                result = session.run("""
                    MATCH (s:SBOM)-[:DESCRIBES]->(a:Artifact)
                    RETURN s.sbom_id as sbom_id, a.path as artifact_path,
                           a.hash as artifact_hash, s.created_at as created_at
                    ORDER BY s.created_at DESC
                    LIMIT $limit
                """, {"limit": limit})
                
                artifacts = []
                for record in result:
                    artifacts.append({
                        "sbom_id": record["sbom_id"],
                        "artifact_path": record["artifact_path"],
                        "artifact_hash": record["artifact_hash"][:16] + "...",
                        "created_at": record["created_at"],
                        "is_signed": False
                    })
                
                return artifacts
        except Exception as e:
            print(f"Failed to get recent artifacts: {e}")
        return []
    
    def _update_stats(self):
        """Update registry statistics."""
        if self.storage_backend:
            try:
                # Get current SBOM count (this is a simple approximation)
                sample_sboms = self.storage_backend.list_sboms(limit=1000)
                self.stats['total_sboms'] = len(sample_sboms)
                
                # Count unique artifacts
                unique_hashes = set()
                for sbom in sample_sboms:
                    if 'artifact_hash' in sbom:
                        unique_hashes.add(sbom['artifact_hash'])
                
                self.stats['total_artifacts'] = len(unique_hashes)
                self.stats['last_updated'] = datetime.now(timezone.utc).isoformat()
                
            except Exception:
                # If stats update fails, continue silently
                pass


class SBOMRegistryAPI:
    """FastAPI-based REST API for SBOM Registry."""
    
    def __init__(self, registry: SBOMRegistry):
        if not FASTAPI_AVAILABLE:
            raise ImportError("FastAPI is required for the registry API")
        
        self.registry = registry
        self.app = FastAPI(
            title="AI Artifact Supply Chain Trust - SBOM Registry",
            description="REST API for SBOM storage, retrieval, and search",
            version="1.0.0"
        )
        
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup FastAPI routes."""
        
        @self.app.get("/health")
        async def health_check():
            """Health check endpoint."""
            return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}
        
        @self.app.get("/stats")
        async def get_stats():
            """Get registry statistics."""
            return self.registry.get_registry_stats()
        
        @self.app.post("/sboms/")
        async def register_sbom(sbom_data: Dict[str, Any]):
            """Register a new SBOM."""
            result = self.registry.register_sbom(sbom_data)
            if not result['success']:
                raise HTTPException(status_code=400, detail=result['error'])
            return result
        
        @self.app.get("/sboms/{sbom_id}")
        async def get_sbom(sbom_id: str):
            """Get SBOM by ID."""
            sbom = self.registry.get_sbom(sbom_id)
            if not sbom:
                raise HTTPException(status_code=404, detail="SBOM not found")
            return sbom
        
        @self.app.delete("/sboms/{sbom_id}")
        async def delete_sbom(sbom_id: str):
            """Delete SBOM by ID."""
            result = self.registry.delete_sbom(sbom_id)
            if not result['success']:
                raise HTTPException(status_code=404, detail=result['error'])
            return result
        
        @self.app.get("/sboms/")
        async def search_sboms(
            artifact_path: Optional[str] = Query(None, description="Filter by artifact path"),
            artifact_hash: Optional[str] = Query(None, description="Filter by artifact hash"),
            metadata_key: Optional[str] = Query(None, description="Filter by metadata key"),
            limit: int = Query(100, ge=1, le=1000, description="Maximum number of results"),
            offset: int = Query(0, ge=0, description="Number of results to skip")
        ):
            """Search and list SBOMs."""
            if any([artifact_path, artifact_hash, metadata_key]):
                # Perform search
                results = self.registry.search_sboms(
                    artifact_path=artifact_path,
                    artifact_hash=artifact_hash,
                    metadata_key=metadata_key,
                    limit=limit
                )
                return {
                    'sboms': results,
                    'search_criteria': {
                        'artifact_path': artifact_path,
                        'artifact_hash': artifact_hash,
                        'metadata_key': metadata_key
                    },
                    'count': len(results)
                }
            else:
                # List all SBOMs with pagination
                return self.registry.list_sboms(limit=limit, offset=offset)
        
        @self.app.get("/artifacts/{artifact_hash}/verify")
        async def verify_artifact(artifact_hash: str):
            """Verify if an artifact is registered."""
            return self.registry.verify_artifact_in_registry(artifact_hash)
    
    def run(self, host: str = "0.0.0.0", port: int = 8001, debug: bool = False):
        """Run the API server."""
        uvicorn.run(self.app, host=host, port=port, debug=debug)


def create_registry_from_config(config: Dict[str, Any]) -> SBOMRegistry:
    """
    Create SBOM registry from configuration.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        SBOMRegistry instance
    """
    storage_type = config.get('storage_type', 'local')
    
    if storage_type == 'local':
        storage_path = config.get('storage_path', 'data/sboms')
        storage_backend = LocalStorageBackend(storage_path)
    elif storage_type == 'neo4j':
        uri = config.get('neo4j_uri', 'bolt://localhost:7687')
        username = config.get('neo4j_username', 'neo4j')
        password = config.get('neo4j_password', 'password')
        storage_backend = Neo4jStorageBackend(uri, username, password)
    else:
        raise ValueError(f"Unsupported storage type: {storage_type}")
    
    return SBOMRegistry(storage_backend)