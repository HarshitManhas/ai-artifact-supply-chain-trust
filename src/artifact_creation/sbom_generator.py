"""
SBOM Generator Module

Generates Software Bill of Materials (SBOM) entries for AI artifacts with
cryptographic fingerprints (SHA-256) and comprehensive metadata.
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any
import uuid

from .metadata_extractor import MetadataExtractor
from .artifact_analyzer import ArtifactAnalyzer


class SBOMEntry:
    """Represents a single SBOM entry for an AI artifact."""
    
    def __init__(self, 
                 artifact_path: str,
                 artifact_hash: str,
                 metadata: Dict[str, Any],
                 dependencies: Optional[List[Dict[str, Any]]] = None):
        self.artifact_path = artifact_path
        self.artifact_hash = artifact_hash
        self.metadata = metadata
        self.dependencies = dependencies or []
        self.sbom_id = str(uuid.uuid4())
        self.created_at = datetime.now(timezone.utc).isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert SBOM entry to dictionary format."""
        return {
            'sbom_id': self.sbom_id,
            'artifact_path': self.artifact_path,
            'artifact_hash': self.artifact_hash,
            'metadata': self.metadata,
            'dependencies': self.dependencies,
            'created_at': self.created_at
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Convert SBOM entry to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


class SBOMGenerator:
    """Generates SBOM entries for AI artifacts."""
    
    def __init__(self):
        self.metadata_extractor = MetadataExtractor()
        self.artifact_analyzer = ArtifactAnalyzer()
    
    def calculate_hash(self, file_path: str, algorithm: str = 'sha256') -> str:
        """
        Calculate cryptographic hash of an artifact.
        
        Args:
            file_path: Path to the artifact file
            algorithm: Hash algorithm to use (default: sha256)
            
        Returns:
            Hexadecimal hash string
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Artifact not found: {file_path}")
        
        hasher = getattr(hashlib, algorithm)()
        
        with open(file_path, 'rb') as f:
            # Read file in chunks to handle large files efficiently
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        
        return hasher.hexdigest()
    
    def create_sbom(self, 
                   artifact_path: str,
                   include_dependencies: bool = True,
                   additional_metadata: Optional[Dict[str, Any]] = None) -> SBOMEntry:
        """
        Create a complete SBOM entry for an AI artifact.
        
        Args:
            artifact_path: Path to the AI artifact
            include_dependencies: Whether to analyze and include dependencies
            additional_metadata: Additional metadata to include
            
        Returns:
            SBOMEntry object
        """
        if not os.path.exists(artifact_path):
            raise FileNotFoundError(f"Artifact not found: {artifact_path}")
        
        # Calculate cryptographic hash
        artifact_hash = self.calculate_hash(artifact_path)
        
        # Extract metadata
        metadata = self.metadata_extractor.extract_metadata(artifact_path)
        
        # Add additional metadata if provided
        if additional_metadata:
            metadata.update(additional_metadata)
        
        # Analyze dependencies if requested
        dependencies = []
        if include_dependencies:
            dependencies = self.artifact_analyzer.analyze_dependencies(artifact_path)
        
        return SBOMEntry(
            artifact_path=artifact_path,
            artifact_hash=artifact_hash,
            metadata=metadata,
            dependencies=dependencies
        )
    
    def create_batch_sbom(self, 
                         artifact_paths: List[str],
                         include_dependencies: bool = True) -> List[SBOMEntry]:
        """
        Create SBOM entries for multiple artifacts.
        
        Args:
            artifact_paths: List of paths to AI artifacts
            include_dependencies: Whether to analyze and include dependencies
            
        Returns:
            List of SBOMEntry objects
        """
        sbom_entries = []
        
        for path in artifact_paths:
            try:
                sbom_entry = self.create_sbom(path, include_dependencies)
                sbom_entries.append(sbom_entry)
            except Exception as e:
                print(f"Warning: Failed to create SBOM for {path}: {e}")
                continue
        
        return sbom_entries
    
    def save_sbom(self, sbom_entry: SBOMEntry, output_path: str) -> None:
        """
        Save SBOM entry to a JSON file.
        
        Args:
            sbom_entry: SBOM entry to save
            output_path: Path where to save the SBOM file
        """
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        with open(output_path, 'w') as f:
            f.write(sbom_entry.to_json())
    
    def load_sbom(self, sbom_path: str) -> SBOMEntry:
        """
        Load SBOM entry from a JSON file.
        
        Args:
            sbom_path: Path to the SBOM JSON file
            
        Returns:
            SBOMEntry object
        """
        if not os.path.exists(sbom_path):
            raise FileNotFoundError(f"SBOM file not found: {sbom_path}")
        
        with open(sbom_path, 'r') as f:
            data = json.load(f)
        
        return SBOMEntry(
            artifact_path=data['artifact_path'],
            artifact_hash=data['artifact_hash'],
            metadata=data['metadata'],
            dependencies=data.get('dependencies', [])
        )
    
    def verify_artifact_integrity(self, 
                                 artifact_path: str, 
                                 sbom_entry: SBOMEntry) -> bool:
        """
        Verify that an artifact matches its SBOM entry.
        
        Args:
            artifact_path: Path to the artifact to verify
            sbom_entry: SBOM entry to verify against
            
        Returns:
            True if artifact integrity is verified, False otherwise
        """
        if not os.path.exists(artifact_path):
            return False
        
        # Calculate current hash
        current_hash = self.calculate_hash(artifact_path)
        
        # Compare with SBOM hash
        return current_hash == sbom_entry.artifact_hash
