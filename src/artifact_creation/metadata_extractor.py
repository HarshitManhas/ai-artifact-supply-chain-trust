"""
Metadata Extractor Module

Extracts comprehensive metadata from AI artifacts including file information,
creation details, and artifact-specific properties.
"""

import os
import stat
import platform
import getpass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional
import mimetypes
import pickle
import json


class MetadataExtractor:
    """Extracts metadata from AI artifacts."""
    
    def __init__(self):
        self.supported_extensions = {
            '.pkl', '.pickle',  # Pickle files
            '.json',  # JSON configuration files
            '.yaml', '.yml',  # YAML configuration files
            '.py',  # Python scripts
            '.h5', '.hdf5',  # HDF5 model files
            '.onnx',  # ONNX model files
            '.pb',  # TensorFlow protobuf files
            '.pth', '.pt',  # PyTorch model files
            '.joblib',  # Joblib files
            '.csv', '.parquet',  # Dataset files
            '.txt', '.log',  # Text and log files
        }
    
    def extract_metadata(self, artifact_path: str) -> Dict[str, Any]:
        """
        Extract comprehensive metadata from an AI artifact.
        
        Args:
            artifact_path: Path to the AI artifact
            
        Returns:
            Dictionary containing metadata
        """
        if not os.path.exists(artifact_path):
            raise FileNotFoundError(f"Artifact not found: {artifact_path}")
        
        metadata = {}
        
        # Basic file information
        metadata.update(self._extract_file_info(artifact_path))
        
        # System and environment information
        metadata.update(self._extract_system_info())
        
        # Artifact-specific metadata
        metadata.update(self._extract_artifact_specific_metadata(artifact_path))
        
        return metadata
    
    def _extract_file_info(self, file_path: str) -> Dict[str, Any]:
        """Extract basic file information."""
        file_stat = os.stat(file_path)
        file_path_obj = Path(file_path)
        
        return {
            'file_info': {
                'name': file_path_obj.name,
                'stem': file_path_obj.stem,
                'suffix': file_path_obj.suffix,
                'absolute_path': os.path.abspath(file_path),
                'size_bytes': file_stat.st_size,
                'size_human': self._format_bytes(file_stat.st_size),
                'created_time': datetime.fromtimestamp(file_stat.st_ctime, tz=timezone.utc).isoformat(),
                'modified_time': datetime.fromtimestamp(file_stat.st_mtime, tz=timezone.utc).isoformat(),
                'accessed_time': datetime.fromtimestamp(file_stat.st_atime, tz=timezone.utc).isoformat(),
                'permissions': oct(file_stat.st_mode),
                'owner_uid': file_stat.st_uid,
                'group_gid': file_stat.st_gid,
                'mime_type': mimetypes.guess_type(file_path)[0]
            }\n        }\n    \n    def _extract_system_info(self) -> Dict[str, Any]:\n        \"\"\"Extract system and environment information.\"\"\"\n        return {\n            'system_info': {\n                'platform': platform.platform(),\n                'system': platform.system(),\n                'release': platform.release(),\n                'version': platform.version(),\n                'machine': platform.machine(),\n                'processor': platform.processor(),\n                'python_version': platform.python_version(),\n                'hostname': platform.node(),\n                'username': getpass.getuser(),\n                'extraction_timestamp': datetime.now(timezone.utc).isoformat()\n            }\n        }\n    \n    def _extract_artifact_specific_metadata(self, file_path: str) -> Dict[str, Any]:\n        \"\"\"Extract artifact-specific metadata based on file type.\"\"\"\n        file_path_obj = Path(file_path)\n        suffix = file_path_obj.suffix.lower()\n        \n        artifact_metadata = {'artifact_type': 'unknown'}\n        \n        try:\n            if suffix in {'.pkl', '.pickle'}:\n                artifact_metadata.update(self._extract_pickle_metadata(file_path))\n            elif suffix == '.json':\n                artifact_metadata.update(self._extract_json_metadata(file_path))\n            elif suffix in {'.yaml', '.yml'}:\n                artifact_metadata.update(self._extract_yaml_metadata(file_path))\n            elif suffix == '.py':\n                artifact_metadata.update(self._extract_python_metadata(file_path))\n            elif suffix in {'.h5', '.hdf5'}:\n                artifact_metadata.update(self._extract_hdf5_metadata(file_path))\n            elif suffix == '.onnx':\n                artifact_metadata.update(self._extract_onnx_metadata(file_path))\n            elif suffix in {'.pth', '.pt'}:\n                artifact_metadata.update(self._extract_pytorch_metadata(file_path))\n            elif suffix in {'.csv', '.parquet'}:\n                artifact_metadata.update(self._extract_dataset_metadata(file_path))\n            \n        except Exception as e:\n            artifact_metadata['extraction_error'] = str(e)\n        \n        return {'artifact_metadata': artifact_metadata}\n    \n    def _extract_pickle_metadata(self, file_path: str) -> Dict[str, Any]:\n        \"\"\"Extract metadata from pickle files.\"\"\"\n        metadata = {'artifact_type': 'pickle'}\n        \n        try:\n            with open(file_path, 'rb') as f:\n                # Try to load and inspect pickle content\n                obj = pickle.load(f)\n                \n                metadata['content_type'] = type(obj).__name__\n                metadata['content_module'] = type(obj).__module__\n                \n                if hasattr(obj, '__dict__'):\n                    metadata['has_attributes'] = True\n                    metadata['attribute_count'] = len(obj.__dict__)\n                \n                if hasattr(obj, 'shape'):\n                    metadata['shape'] = list(obj.shape)\n                \n                if hasattr(obj, '__len__'):\n                    try:\n                        metadata['length'] = len(obj)\n                    except:\n                        pass\n        \n        except Exception as e:\n            metadata['load_error'] = str(e)\n        \n        return metadata\n    \n    def _extract_json_metadata(self, file_path: str) -> Dict[str, Any]:\n        \"\"\"Extract metadata from JSON files.\"\"\"\n        metadata = {'artifact_type': 'json_config'}\n        \n        try:\n            with open(file_path, 'r') as f:\n                data = json.load(f)\n                \n                metadata['json_type'] = type(data).__name__\n                \n                if isinstance(data, dict):\n                    metadata['key_count'] = len(data)\n                    metadata['top_level_keys'] = list(data.keys())[:10]  # First 10 keys\n                elif isinstance(data, list):\n                    metadata['item_count'] = len(data)\n        \n        except Exception as e:\n            metadata['parse_error'] = str(e)\n        \n        return metadata\n    \n    def _extract_yaml_metadata(self, file_path: str) -> Dict[str, Any]:\n        \"\"\"Extract metadata from YAML files.\"\"\"\n        metadata = {'artifact_type': 'yaml_config'}\n        \n        try:\n            import yaml\n            with open(file_path, 'r') as f:\n                data = yaml.safe_load(f)\n                \n                metadata['yaml_type'] = type(data).__name__\n                \n                if isinstance(data, dict):\n                    metadata['key_count'] = len(data)\n                    metadata['top_level_keys'] = list(data.keys())[:10]\n        \n        except ImportError:\n            metadata['error'] = 'PyYAML not installed'\n        except Exception as e:\n            metadata['parse_error'] = str(e)\n        \n        return metadata\n    \n    def _extract_python_metadata(self, file_path: str) -> Dict[str, Any]:\n        \"\"\"Extract metadata from Python scripts.\"\"\"\n        metadata = {'artifact_type': 'python_script'}\n        \n        try:\n            with open(file_path, 'r', encoding='utf-8') as f:\n                content = f.read()\n                \n                metadata['line_count'] = len(content.splitlines())\n                metadata['char_count'] = len(content)\n                \n                # Basic analysis\n                metadata['has_main'] = 'if __name__ == \"__main__\"' in content\n                metadata['import_count'] = content.count('import ')\n                \n        except Exception as e:\n            metadata['read_error'] = str(e)\n        \n        return metadata\n    \n    def _extract_hdf5_metadata(self, file_path: str) -> Dict[str, Any]:\n        \"\"\"Extract metadata from HDF5 files (ML models).\"\"\"\n        metadata = {'artifact_type': 'hdf5_model'}\n        \n        try:\n            import h5py\n            with h5py.File(file_path, 'r') as f:\n                metadata['group_count'] = len(f.keys())\n                metadata['top_level_groups'] = list(f.keys())[:10]\n                \n        except ImportError:\n            metadata['error'] = 'h5py not installed'\n        except Exception as e:\n            metadata['read_error'] = str(e)\n        \n        return metadata\n    \n    def _extract_onnx_metadata(self, file_path: str) -> Dict[str, Any]:\n        \"\"\"Extract metadata from ONNX model files.\"\"\"\n        metadata = {'artifact_type': 'onnx_model'}\n        \n        try:\n            import onnx\n            model = onnx.load(file_path)\n            \n            metadata['opset_version'] = model.opset_import[0].version if model.opset_import else None\n            metadata['input_count'] = len(model.graph.input)\n            metadata['output_count'] = len(model.graph.output)\n            metadata['node_count'] = len(model.graph.node)\n            \n        except ImportError:\n            metadata['error'] = 'onnx not installed'\n        except Exception as e:\n            metadata['read_error'] = str(e)\n        \n        return metadata\n    \n    def _extract_pytorch_metadata(self, file_path: str) -> Dict[str, Any]:\n        \"\"\"Extract metadata from PyTorch model files.\"\"\"\n        metadata = {'artifact_type': 'pytorch_model'}\n        \n        try:\n            import torch\n            \n            # Load model checkpoint info (without loading the full model)\n            checkpoint = torch.load(file_path, map_location='cpu')\n            \n            metadata['checkpoint_type'] = type(checkpoint).__name__\n            \n            if isinstance(checkpoint, dict):\n                metadata['checkpoint_keys'] = list(checkpoint.keys())\n                \n                if 'state_dict' in checkpoint:\n                    state_dict = checkpoint['state_dict']\n                    metadata['parameter_count'] = len(state_dict)\n                    \n        except ImportError:\n            metadata['error'] = 'torch not installed'\n        except Exception as e:\n            metadata['read_error'] = str(e)\n        \n        return metadata\n    \n    def _extract_dataset_metadata(self, file_path: str) -> Dict[str, Any]:\n        \"\"\"Extract metadata from dataset files.\"\"\"\n        file_path_obj = Path(file_path)\n        suffix = file_path_obj.suffix.lower()\n        \n        metadata = {'artifact_type': f'dataset_{suffix[1:]}'}\n        \n        try:\n            if suffix == '.csv':\n                import pandas as pd\n                df = pd.read_csv(file_path, nrows=0)  # Just read header\n                metadata['column_count'] = len(df.columns)\n                metadata['column_names'] = list(df.columns)[:20]  # First 20 columns\n                \n                # Try to get row count efficiently\n                with open(file_path, 'r') as f:\n                    row_count = sum(1 for _ in f) - 1  # Subtract header\n                metadata['row_count'] = row_count\n                \n            elif suffix == '.parquet':\n                import pandas as pd\n                df = pd.read_parquet(file_path)\n                metadata['column_count'] = len(df.columns)\n                metadata['row_count'] = len(df)\n                metadata['column_names'] = list(df.columns)[:20]\n                \n        except ImportError as e:\n            metadata['error'] = f'Required library not installed: {e}'\n        except Exception as e:\n            metadata['read_error'] = str(e)\n        \n        return metadata\n    \n    def _format_bytes(self, size: int) -> str:\n        \"\"\"Format byte size in human readable format.\"\"\"\n        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:\n            if size < 1024.0:\n                return f\"{size:.2f} {unit}\"\n            size /= 1024.0\n        return f\"{size:.2f} PB\"\n    \n    def get_supported_extensions(self) -> set:\n        \"\"\"Return set of supported file extensions.\"\"\"\n        return self.supported_extensions.copy()
