"""
Artifact Analyzer Module

Analyzes AI artifacts to determine dependencies and relationships for SBOM entries.
"""

from pathlib import Path
from typing import Dict, List, Any
import os
import re
import json


class ArtifactAnalyzer:
    """Analyzes AI artifacts for dependencies and relationships."""
    
    def analyze_dependencies(self, artifact_path: str) -> List[Dict[str, Any]]:
        """
        Analyze dependencies for a given artifact.
        
        Currently supports:
        - Python scripts: import/module dependencies
        - JSON/YAML configs: embedded references
        - Model checkpoints: placeholder for future extraction
        
        Args:
            artifact_path: Path to the AI artifact
            
        Returns:
            List of dependency descriptors
        """
        path = Path(artifact_path)
        suffix = path.suffix.lower()
        
        if suffix == '.py':
            return self._analyze_python_dependencies(path)
        elif suffix in {'.json'}:
            return self._analyze_json_dependencies(path)
        elif suffix in {'.yaml', '.yml'}:
            return self._analyze_yaml_dependencies(path)
        
        # Default: no dependencies identified
        return []
    
    def _analyze_python_dependencies(self, path: Path) -> List[Dict[str, Any]]:
        deps: List[Dict[str, Any]] = []
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            pattern = re.compile(r'^(?:from\s+([\w\.]+)\s+import|import\s+([\w\.]+))', re.MULTILINE)
            modules = set()
            for m in pattern.finditer(content):
                mod = m.group(1) or m.group(2)
                if mod:
                    modules.add(mod.split('.')[0])
            for mod in sorted(modules):
                deps.append({'type': 'python_module', 'name': mod})
        except Exception as e:
            deps.append({'type': 'error', 'message': str(e)})
        return deps
    
    def _analyze_json_dependencies(self, path: Path) -> List[Dict[str, Any]]:
        deps: List[Dict[str, Any]] = []
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            # Simple heuristic: look for keys that look like paths
            def walk(obj):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        if isinstance(v, str) and (v.endswith(('.pkl', '.pt', '.pth', '.h5', '.onnx', '.csv', '.parquet', '.json', '.yaml', '.yml')) or os.path.sep in v):
                            deps.append({'type': 'file_reference', 'path': v})
                        else:
                            walk(v)
                elif isinstance(obj, list):
                    for item in obj:
                        walk(item)
            walk(data)
        except Exception as e:
            deps.append({'type': 'error', 'message': str(e)})
        return deps
    
    def _analyze_yaml_dependencies(self, path: Path) -> List[Dict[str, Any]]:
        deps: List[Dict[str, Any]] = []
        try:
            import yaml
            with open(path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            # Reuse JSON logic
            def walk(obj):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        if isinstance(v, str) and (v.endswith(('.pkl', '.pt', '.pth', '.h5', '.onnx', '.csv', '.parquet', '.json', '.yaml', '.yml')) or os.path.sep in v):
                            deps.append({'type': 'file_reference', 'path': v})
                        else:
                            walk(v)
                elif isinstance(obj, list):
                    for item in obj:
                        walk(item)
            walk(data)
        except Exception as e:
            deps.append({'type': 'error', 'message': str(e)})
        return deps

