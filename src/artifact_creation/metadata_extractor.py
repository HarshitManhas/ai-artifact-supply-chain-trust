"""
Metadata Extractor Module

Extracts comprehensive metadata from AI artifacts including file information,
creation details, and artifact-specific properties.
"""

import os
import platform
import getpass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any
import mimetypes
import pickle
import json


class MetadataExtractor:
    """Extracts metadata from AI artifacts."""

    def __init__(self):
        self.supported_extensions = {
            '.pkl', '.pickle',
            '.json',
            '.yaml', '.yml',
            '.py',
            '.h5', '.hdf5',
            '.onnx',
            '.pb',
            '.pth', '.pt',
            '.joblib',
            '.csv', '.parquet',
            '.txt', '.log',
        }

    def extract_metadata(self, artifact_path: str) -> Dict[str, Any]:
        """Extract comprehensive metadata from an AI artifact."""
        if not os.path.exists(artifact_path):
            raise FileNotFoundError(f"Artifact not found: {artifact_path}")

        metadata: Dict[str, Any] = {}
        metadata.update(self._extract_file_info(artifact_path))
        metadata.update(self._extract_system_info())
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
                'mime_type': mimetypes.guess_type(file_path)[0],
            }
        }

    def _extract_system_info(self) -> Dict[str, Any]:
        """Extract system and environment information."""
        return {
            'system_info': {
                'platform': platform.platform(),
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'python_version': platform.python_version(),
                'hostname': platform.node(),
                'username': getpass.getuser(),
                'extraction_timestamp': datetime.now(timezone.utc).isoformat(),
            }
        }

    def _extract_artifact_specific_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract artifact-specific metadata based on file type."""
        suffix = Path(file_path).suffix.lower()
        artifact_metadata: Dict[str, Any] = {'artifact_type': 'unknown'}
        try:
            if suffix in {'.pkl', '.pickle'}:
                artifact_metadata.update(self._extract_pickle_metadata(file_path))
            elif suffix == '.json':
                artifact_metadata.update(self._extract_json_metadata(file_path))
            elif suffix in {'.yaml', '.yml'}:
                artifact_metadata.update(self._extract_yaml_metadata(file_path))
            elif suffix == '.py':
                artifact_metadata.update(self._extract_python_metadata(file_path))
            elif suffix in {'.h5', '.hdf5'}:
                artifact_metadata.update(self._extract_hdf5_metadata(file_path))
            elif suffix == '.onnx':
                artifact_metadata.update(self._extract_onnx_metadata(file_path))
            elif suffix in {'.pth', '.pt'}:
                artifact_metadata.update(self._extract_pytorch_metadata(file_path))
            elif suffix in {'.csv', '.parquet'}:
                artifact_metadata.update(self._extract_dataset_metadata(file_path))
        except Exception as e:
            artifact_metadata['extraction_error'] = str(e)
        return {'artifact_metadata': artifact_metadata}

    def _extract_pickle_metadata(self, file_path: str) -> Dict[str, Any]:
        metadata: Dict[str, Any] = {'artifact_type': 'pickle'}
        try:
            with open(file_path, 'rb') as f:
                obj = pickle.load(f)
                metadata['content_type'] = type(obj).__name__
                metadata['content_module'] = type(obj).__module__
                if hasattr(obj, '__dict__'):
                    metadata['has_attributes'] = True
                    metadata['attribute_count'] = len(obj.__dict__)
                if hasattr(obj, 'shape'):
                    try:
                        metadata['shape'] = list(obj.shape)  # type: ignore[attr-defined]
                    except Exception:
                        pass
                if hasattr(obj, '__len__'):
                    try:
                        metadata['length'] = len(obj)  # type: ignore[arg-type]
                    except Exception:
                        pass
        except Exception as e:
            metadata['load_error'] = str(e)
        return metadata

    def _extract_json_metadata(self, file_path: str) -> Dict[str, Any]:
        metadata: Dict[str, Any] = {'artifact_type': 'json_config'}
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                metadata['json_type'] = type(data).__name__
                if isinstance(data, dict):
                    metadata['key_count'] = len(data)
                    metadata['top_level_keys'] = list(data.keys())[:10]
                elif isinstance(data, list):
                    metadata['item_count'] = len(data)
        except Exception as e:
            metadata['parse_error'] = str(e)
        return metadata

    def _extract_yaml_metadata(self, file_path: str) -> Dict[str, Any]:
        metadata: Dict[str, Any] = {'artifact_type': 'yaml_config'}
        try:
            import yaml
            with open(file_path, 'r') as f:
                data = yaml.safe_load(f)
                metadata['yaml_type'] = type(data).__name__
                if isinstance(data, dict):
                    metadata['key_count'] = len(data)
                    metadata['top_level_keys'] = list(data.keys())[:10]
        except ImportError:
            metadata['error'] = 'PyYAML not installed'
        except Exception as e:
            metadata['parse_error'] = str(e)
        return metadata

    def _extract_python_metadata(self, file_path: str) -> Dict[str, Any]:
        metadata: Dict[str, Any] = {'artifact_type': 'python_script'}
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                metadata['line_count'] = len(content.splitlines())
                metadata['char_count'] = len(content)
                metadata['has_main'] = 'if __name__ == "__main__"' in content
                metadata['import_count'] = content.count('import ')
        except Exception as e:
            metadata['read_error'] = str(e)
        return metadata

    def _extract_hdf5_metadata(self, file_path: str) -> Dict[str, Any]:
        metadata: Dict[str, Any] = {'artifact_type': 'hdf5_model'}
        try:
            import h5py
            with h5py.File(file_path, 'r') as f:
                metadata['group_count'] = len(f.keys())
                metadata['top_level_groups'] = list(f.keys())[:10]
        except ImportError:
            metadata['error'] = 'h5py not installed'
        except Exception as e:
            metadata['read_error'] = str(e)
        return metadata

    def _extract_onnx_metadata(self, file_path: str) -> Dict[str, Any]:
        metadata: Dict[str, Any] = {'artifact_type': 'onnx_model'}
        try:
            import onnx
            model = onnx.load(file_path)
            metadata['opset_version'] = model.opset_import[0].version if model.opset_import else None
            metadata['input_count'] = len(model.graph.input)
            metadata['output_count'] = len(model.graph.output)
            metadata['node_count'] = len(model.graph.node)
        except ImportError:
            metadata['error'] = 'onnx not installed'
        except Exception as e:
            metadata['read_error'] = str(e)
        return metadata

    def _extract_pytorch_metadata(self, file_path: str) -> Dict[str, Any]:
        metadata: Dict[str, Any] = {'artifact_type': 'pytorch_model'}
        try:
            import torch
            checkpoint = torch.load(file_path, map_location='cpu')
            metadata['checkpoint_type'] = type(checkpoint).__name__
            if isinstance(checkpoint, dict):
                metadata['checkpoint_keys'] = list(checkpoint.keys())
                if 'state_dict' in checkpoint:
                    state_dict = checkpoint['state_dict']
                    try:
                        metadata['parameter_count'] = len(state_dict)
                    except Exception:
                        pass
        except ImportError:
            metadata['error'] = 'torch not installed'
        except Exception as e:
            metadata['read_error'] = str(e)
        return metadata

    def _extract_dataset_metadata(self, file_path: str) -> Dict[str, Any]:
        suffix = Path(file_path).suffix.lower()
        metadata: Dict[str, Any] = {'artifact_type': f'dataset_{suffix[1:]}'}
        try:
            if suffix == '.csv':
                import pandas as pd
                df = pd.read_csv(file_path, nrows=0)
                metadata['column_count'] = len(df.columns)
                metadata['column_names'] = list(df.columns)[:20]
                with open(file_path, 'r') as f:
                    row_count = sum(1 for _ in f) - 1
                metadata['row_count'] = max(row_count, 0)
            elif suffix == '.parquet':
                import pandas as pd
                df = pd.read_parquet(file_path)
                metadata['column_count'] = len(df.columns)
                metadata['row_count'] = len(df)
                metadata['column_names'] = list(df.columns)[:20]
        except ImportError as e:
            metadata['error'] = f'Required library not installed: {e}'
        except Exception as e:
            metadata['read_error'] = str(e)
        return metadata

    def _format_bytes(self, size: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"

    def get_supported_extensions(self) -> set:
        """Return set of supported file extensions."""
        return self.supported_extensions.copy()
