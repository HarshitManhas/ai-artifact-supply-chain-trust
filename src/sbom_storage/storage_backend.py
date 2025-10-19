"""
Storage Backend Module

Provides different storage backends for SBOM data including local file system
and Neo4j graph database storage.
"""

import os
import json
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Union
from pathlib import Path

# Optional Neo4j import
try:
    from neo4j import GraphDatabase
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False


class StorageBackend(ABC):
    """Abstract base class for SBOM storage backends."""
    
    @abstractmethod
    def store_sbom(self, sbom_data: Dict[str, Any]) -> str:
        """Store SBOM data and return a unique identifier."""
        pass
    
    @abstractmethod
    def retrieve_sbom(self, sbom_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve SBOM data by ID."""
        pass
    
    @abstractmethod
    def search_sboms(self, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Search for SBOMs matching the query criteria."""
        pass
    
    @abstractmethod
    def delete_sbom(self, sbom_id: str) -> bool:
        """Delete SBOM by ID. Returns True if successful."""
        pass
    
    @abstractmethod
    def list_sboms(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """List SBOMs with pagination."""
        pass


class LocalStorageBackend(StorageBackend):
    """Local file system storage backend for SBOMs."""
    
    def __init__(self, storage_path: str = "data/sboms"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # Create index file if it doesn't exist
        self.index_file = self.storage_path / "index.json"
        if not self.index_file.exists():
            self._initialize_index()
    
    def _initialize_index(self):
        """Initialize the SBOM index file."""
        index_data = {
            "sboms": {},
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_updated": datetime.now(timezone.utc).isoformat()
        }
        with open(self.index_file, 'w') as f:
            json.dump(index_data, f, indent=2)
    
    def _load_index(self) -> Dict[str, Any]:
        """Load the SBOM index."""
        with open(self.index_file, 'r') as f:
            return json.load(f)
    
    def _save_index(self, index_data: Dict[str, Any]):
        """Save the SBOM index."""
        index_data["last_updated"] = datetime.now(timezone.utc).isoformat()
        with open(self.index_file, 'w') as f:
            json.dump(index_data, f, indent=2)
    
    def store_sbom(self, sbom_data: Dict[str, Any]) -> str:
        """Store SBOM data in local file system."""
        # Generate unique ID if not present
        sbom_id = sbom_data.get('sbom_id', str(uuid.uuid4()))
        
        # Create file path
        sbom_file = self.storage_path / f"{sbom_id}.json"
        
        # Add storage metadata
        storage_metadata = {
            "stored_at": datetime.now(timezone.utc).isoformat(),
            "storage_backend": "local",
            "file_path": str(sbom_file)
        }
        sbom_data_with_metadata = {
            **sbom_data,
            "storage_metadata": storage_metadata
        }
        
        # Save SBOM file
        with open(sbom_file, 'w') as f:
            json.dump(sbom_data_with_metadata, f, indent=2)
        
        # Update index
        index_data = self._load_index()
        index_data["sboms"][sbom_id] = {
            "sbom_id": sbom_id,
            "file_path": str(sbom_file),
            "artifact_path": sbom_data.get('artifact_path'),
            "artifact_hash": sbom_data.get('artifact_hash'),
            "stored_at": storage_metadata["stored_at"],
            "metadata_keys": list(sbom_data.get('metadata', {}).keys())
        }
        self._save_index(index_data)
        
        return sbom_id
    
    def retrieve_sbom(self, sbom_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve SBOM data by ID."""
        sbom_file = self.storage_path / f"{sbom_id}.json"
        
        if not sbom_file.exists():
            return None
        
        try:
            with open(sbom_file, 'r') as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError):
            return None
    
    def search_sboms(self, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Search for SBOMs matching the query criteria."""
        index_data = self._load_index()
        results = []
        
        for sbom_id, sbom_info in index_data["sboms"].items():
            match = True
            
            # Check each query criterion
            for key, value in query.items():
                if key == "artifact_path":
                    if value not in (sbom_info.get("artifact_path") or ""):
                        match = False
                        break
                elif key == "artifact_hash":
                    if sbom_info.get("artifact_hash") != value:
                        match = False
                        break
                elif key == "metadata_key":
                    if value not in sbom_info.get("metadata_keys", []):
                        match = False
                        break
            
            if match:
                # Load full SBOM data
                full_sbom = self.retrieve_sbom(sbom_id)
                if full_sbom:
                    results.append(full_sbom)
        
        return results
    
    def delete_sbom(self, sbom_id: str) -> bool:
        """Delete SBOM by ID."""
        sbom_file = self.storage_path / f"{sbom_id}.json"
        
        if not sbom_file.exists():
            return False
        
        try:
            # Remove file
            sbom_file.unlink()
            
            # Update index
            index_data = self._load_index()
            if sbom_id in index_data["sboms"]:
                del index_data["sboms"][sbom_id]
                self._save_index(index_data)
            
            return True
        except (OSError, IOError):
            return False
    
    def list_sboms(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """List SBOMs with pagination."""
        index_data = self._load_index()
        sbom_ids = list(index_data["sboms"].keys())[offset:offset + limit]
        
        results = []
        for sbom_id in sbom_ids:
            sbom_data = self.retrieve_sbom(sbom_id)
            if sbom_data:
                results.append(sbom_data)
        
        return results


class Neo4jStorageBackend(StorageBackend):
    """Neo4j graph database storage backend for SBOMs."""
    
    def __init__(self, uri: str, username: str, password: str):
        if not NEO4J_AVAILABLE:
            raise ImportError("neo4j driver is required for Neo4j storage backend")
        
        self.driver = GraphDatabase.driver(uri, auth=(username, password))
        self._initialize_database()
    
    def _initialize_database(self):
        """Initialize the Neo4j database with required constraints and indexes."""
        with self.driver.session() as session:
            # Create constraints
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (s:SBOM) REQUIRE s.sbom_id IS UNIQUE")
            session.run("CREATE CONSTRAINT IF NOT EXISTS FOR (a:Artifact) REQUIRE a.hash IS UNIQUE")
            
            # Create indexes
            session.run("CREATE INDEX IF NOT EXISTS FOR (s:SBOM) ON (s.artifact_path)")
            session.run("CREATE INDEX IF NOT EXISTS FOR (a:Artifact) ON (a.path)")
    
    def close(self):
        """Close the database connection."""
        if self.driver:
            self.driver.close()
    
    def store_sbom(self, sbom_data: Dict[str, Any]) -> str:
        """Store SBOM data in Neo4j graph database."""
        sbom_id = sbom_data.get('sbom_id', str(uuid.uuid4()))
        
        with self.driver.session() as session:
            # Create SBOM node
            sbom_query = """
            CREATE (s:SBOM {
                sbom_id: $sbom_id,
                artifact_path: $artifact_path,
                artifact_hash: $artifact_hash,
                created_at: $created_at,
                stored_at: $stored_at,
                raw_data: $raw_data
            })
            RETURN s.sbom_id as sbom_id
            """
            
            result = session.run(sbom_query, {
                'sbom_id': sbom_id,
                'artifact_path': sbom_data.get('artifact_path'),
                'artifact_hash': sbom_data.get('artifact_hash'),
                'created_at': sbom_data.get('created_at'),
                'stored_at': datetime.now(timezone.utc).isoformat(),
                'raw_data': json.dumps(sbom_data)
            })
            
            # Create artifact node if it doesn't exist
            artifact_query = """
            MERGE (a:Artifact {hash: $hash})
            SET a.path = $path, a.last_seen = $timestamp
            """
            
            session.run(artifact_query, {
                'hash': sbom_data.get('artifact_hash'),
                'path': sbom_data.get('artifact_path'),
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
            
            # Create relationship between SBOM and Artifact
            relation_query = """
            MATCH (s:SBOM {sbom_id: $sbom_id})
            MATCH (a:Artifact {hash: $hash})
            CREATE (s)-[:DESCRIBES]->(a)
            """
            
            session.run(relation_query, {
                'sbom_id': sbom_id,
                'hash': sbom_data.get('artifact_hash')
            })
            
            # Store dependencies if present
            dependencies = sbom_data.get('dependencies', [])
            for dep in dependencies:
                dep_query = """
                MATCH (s:SBOM {sbom_id: $sbom_id})
                CREATE (d:Dependency {
                    type: $dep_type,
                    name: $name,
                    details: $details
                })
                CREATE (s)-[:HAS_DEPENDENCY]->(d)
                """
                
                session.run(dep_query, {
                    'sbom_id': sbom_id,
                    'dep_type': dep.get('type', 'unknown'),
                    'name': dep.get('name', ''),
                    'details': json.dumps(dep)
                })
        
        return sbom_id
    
    def retrieve_sbom(self, sbom_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve SBOM data by ID."""
        with self.driver.session() as session:
            query = """
            MATCH (s:SBOM {sbom_id: $sbom_id})
            RETURN s.raw_data as raw_data
            """
            
            result = session.run(query, {'sbom_id': sbom_id})
            record = result.single()
            
            if record:
                try:
                    return json.loads(record['raw_data'])
                except json.JSONDecodeError:
                    return None
            
            return None
    
    def search_sboms(self, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Search for SBOMs matching the query criteria."""
        with self.driver.session() as session:
            cypher_query = "MATCH (s:SBOM) WHERE "
            conditions = []
            params = {}
            
            if "artifact_path" in query:
                conditions.append("s.artifact_path CONTAINS $artifact_path")
                params["artifact_path"] = query["artifact_path"]
            
            if "artifact_hash" in query:
                conditions.append("s.artifact_hash = $artifact_hash")
                params["artifact_hash"] = query["artifact_hash"]
            
            if not conditions:
                cypher_query = "MATCH (s:SBOM) RETURN s.raw_data as raw_data LIMIT 100"
            else:
                cypher_query += " AND ".join(conditions) + " RETURN s.raw_data as raw_data"
            
            result = session.run(cypher_query, params)
            
            sboms = []
            for record in result:
                try:
                    sbom_data = json.loads(record['raw_data'])
                    sboms.append(sbom_data)
                except json.JSONDecodeError:
                    continue
            
            return sboms
    
    def delete_sbom(self, sbom_id: str) -> bool:
        """Delete SBOM by ID."""
        with self.driver.session() as session:
            query = """
            MATCH (s:SBOM {sbom_id: $sbom_id})
            OPTIONAL MATCH (s)-[:HAS_DEPENDENCY]->(d:Dependency)
            DELETE s, d
            RETURN count(s) as deleted_count
            """
            
            result = session.run(query, {'sbom_id': sbom_id})
            record = result.single()
            
            return record and record['deleted_count'] > 0
    
    def list_sboms(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """List SBOMs with pagination."""
        with self.driver.session() as session:
            query = """
            MATCH (s:SBOM)
            RETURN s.raw_data as raw_data
            ORDER BY s.stored_at DESC
            SKIP $offset LIMIT $limit
            """
            
            result = session.run(query, {'offset': offset, 'limit': limit})
            
            sboms = []
            for record in result:
                try:
                    sbom_data = json.loads(record['raw_data'])
                    sboms.append(sbom_data)
                except json.JSONDecodeError:
                    continue
            
            return sboms