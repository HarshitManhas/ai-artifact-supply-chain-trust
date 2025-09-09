"""
Test suite for artifact creation module.
"""

import pytest
import tempfile
import os
import json
import pickle
from pathlib import Path

from src.artifact_creation import SBOMGenerator, MetadataExtractor, ArtifactAnalyzer


class TestSBOMGenerator:
    """Test cases for SBOMGenerator class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.generator = SBOMGenerator()
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def create_test_file(self, filename, content):
        """Create a test file with given content."""
        file_path = os.path.join(self.temp_dir, filename)
        
        if filename.endswith('.pkl'):
            with open(file_path, 'wb') as f:
                pickle.dump(content, f)
        elif filename.endswith('.json'):
            with open(file_path, 'w') as f:
                json.dump(content, f)
        else:
            with open(file_path, 'w') as f:
                f.write(content)
        
        return file_path
    
    def test_calculate_hash(self):
        """Test hash calculation for artifacts."""
        # Create test file
        test_content = "test content for hashing"
        test_file = self.create_test_file("test.txt", test_content)
        
        # Calculate hash
        hash_value = self.generator.calculate_hash(test_file)
        
        # Verify hash properties
        assert isinstance(hash_value, str)
        assert len(hash_value) == 64  # SHA-256 hex length
        assert all(c in '0123456789abcdef' for c in hash_value)
        
        # Verify deterministic behavior
        hash_value2 = self.generator.calculate_hash(test_file)
        assert hash_value == hash_value2
    
    def test_create_sbom_basic(self):
        """Test basic SBOM creation."""
        # Create test pickle file
        test_data = {'model': 'test', 'accuracy': 0.95}
        test_file = self.create_test_file("model.pkl", test_data)
        
        # Create SBOM
        sbom_entry = self.generator.create_sbom(test_file)
        
        # Verify SBOM structure
        assert sbom_entry.artifact_path == test_file
        assert len(sbom_entry.artifact_hash) == 64
        assert isinstance(sbom_entry.metadata, dict)
        assert sbom_entry.sbom_id is not None
        assert sbom_entry.created_at is not None
    
    def test_create_sbom_with_metadata(self):
        """Test SBOM creation with additional metadata."""
        test_file = self.create_test_file("config.json", {"key": "value"})
        
        additional_metadata = {
            'creator': 'test-user',
            'version': '1.0.0'
        }
        
        sbom_entry = self.generator.create_sbom(
            test_file, 
            additional_metadata=additional_metadata
        )
        
        # Verify additional metadata is included
        assert 'creator' in sbom_entry.metadata
        assert sbom_entry.metadata['creator'] == 'test-user'
        assert sbom_entry.metadata['version'] == '1.0.0'
    
    def test_create_sbom_nonexistent_file(self):
        """Test SBOM creation with non-existent file."""
        with pytest.raises(FileNotFoundError):
            self.generator.create_sbom("/nonexistent/file.pkl")
    
    def test_create_batch_sbom(self):
        """Test batch SBOM creation."""
        # Create multiple test files
        files = []
        for i in range(3):
            content = f"test content {i}"
            file_path = self.create_test_file(f"file{i}.txt", content)
            files.append(file_path)
        
        # Create batch SBOMs
        sbom_entries = self.generator.create_batch_sbom(files)
        
        assert len(sbom_entries) == 3
        for sbom_entry in sbom_entries:
            assert hasattr(sbom_entry, 'artifact_hash')
            assert hasattr(sbom_entry, 'metadata')
    
    def test_save_and_load_sbom(self):
        """Test SBOM persistence."""
        # Create test file and SBOM
        test_file = self.create_test_file("test.txt", "content")
        sbom_entry = self.generator.create_sbom(test_file)
        
        # Save SBOM
        sbom_path = os.path.join(self.temp_dir, "test_sbom.json")
        self.generator.save_sbom(sbom_entry, sbom_path)
        
        # Verify file was created
        assert os.path.exists(sbom_path)
        
        # Load SBOM
        loaded_sbom = self.generator.load_sbom(sbom_path)
        
        # Verify loaded SBOM matches original
        assert loaded_sbom.artifact_path == sbom_entry.artifact_path
        assert loaded_sbom.artifact_hash == sbom_entry.artifact_hash
    
    def test_verify_artifact_integrity(self):
        """Test artifact integrity verification."""
        # Create test file and SBOM
        test_file = self.create_test_file("test.txt", "original content")
        sbom_entry = self.generator.create_sbom(test_file)
        
        # Verify integrity with unmodified file
        assert self.generator.verify_artifact_integrity(test_file, sbom_entry)
        
        # Modify file
        with open(test_file, 'w') as f:
            f.write("modified content")
        
        # Verify integrity fails with modified file
        assert not self.generator.verify_artifact_integrity(test_file, sbom_entry)


class TestMetadataExtractor:
    """Test cases for MetadataExtractor class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.extractor = MetadataExtractor()
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def create_test_file(self, filename, content):
        """Create a test file with given content."""
        file_path = os.path.join(self.temp_dir, filename)
        
        if filename.endswith('.pkl'):
            with open(file_path, 'wb') as f:
                pickle.dump(content, f)
        elif filename.endswith('.json'):
            with open(file_path, 'w') as f:
                json.dump(content, f)
        else:
            with open(file_path, 'w') as f:
                f.write(content)
        
        return file_path
    
    def test_extract_basic_metadata(self):
        """Test basic metadata extraction."""
        test_file = self.create_test_file("test.txt", "test content")
        
        metadata = self.extractor.extract_metadata(test_file)
        
        # Check required metadata sections
        assert 'file_info' in metadata
        assert 'system_info' in metadata
        assert 'artifact_metadata' in metadata
        
        # Check file info details
        file_info = metadata['file_info']
        assert file_info['name'] == 'test.txt'
        assert file_info['suffix'] == '.txt'
        assert file_info['size_bytes'] > 0
        assert 'created_time' in file_info
        assert 'modified_time' in file_info
    
    def test_extract_json_metadata(self):
        """Test JSON-specific metadata extraction."""
        test_data = {
            'model_name': 'test_model',
            'parameters': {'lr': 0.01, 'epochs': 100}
        }
        test_file = self.create_test_file("config.json", test_data)
        
        metadata = self.extractor.extract_metadata(test_file)
        
        artifact_meta = metadata['artifact_metadata']
        assert artifact_meta['artifact_type'] == 'json_config'
        assert artifact_meta['json_type'] == 'dict'
        assert artifact_meta['key_count'] == 2
        assert 'model_name' in artifact_meta['top_level_keys']
    
    def test_extract_pickle_metadata(self):
        """Test pickle-specific metadata extraction."""
        test_data = {'model': 'logistic_regression', 'accuracy': 0.95}
        test_file = self.create_test_file("model.pkl", test_data)
        
        metadata = self.extractor.extract_metadata(test_file)
        
        artifact_meta = metadata['artifact_metadata']
        assert artifact_meta['artifact_type'] == 'pickle'
        assert artifact_meta['content_type'] == 'dict'
    
    def test_nonexistent_file(self):
        """Test metadata extraction with non-existent file."""
        with pytest.raises(FileNotFoundError):
            self.extractor.extract_metadata("/nonexistent/file.txt")
    
    def test_supported_extensions(self):
        """Test that supported extensions are properly defined."""
        extensions = self.extractor.get_supported_extensions()
        
        assert isinstance(extensions, set)
        assert '.pkl' in extensions
        assert '.json' in extensions
        assert '.py' in extensions


class TestArtifactAnalyzer:
    """Test cases for ArtifactAnalyzer class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = ArtifactAnalyzer()
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def create_test_file(self, filename, content):
        """Create a test file with given content."""
        file_path = os.path.join(self.temp_dir, filename)
        
        if filename.endswith('.json'):
            with open(file_path, 'w') as f:
                json.dump(content, f)
        else:
            with open(file_path, 'w') as f:
                f.write(content)
        
        return file_path
    
    def test_analyze_python_dependencies(self):
        """Test Python dependency analysis."""
        python_code = '''
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt

def main():
    print("Hello World")
'''
        test_file = self.create_test_file("script.py", python_code)
        
        dependencies = self.analyzer.analyze_dependencies(test_file)
        
        # Check that major dependencies are detected
        dep_names = [dep.get('name') for dep in dependencies if dep.get('type') == 'python_module']
        assert 'numpy' in dep_names
        assert 'pandas' in dep_names
        assert 'sklearn' in dep_names
        assert 'matplotlib' in dep_names
    
    def test_analyze_json_dependencies(self):
        """Test JSON dependency analysis."""
        json_data = {
            'model_path': '/path/to/model.pkl',
            'config': {
                'data_file': 'dataset.csv',
                'weights': 'model_weights.h5'
            }
        }
        test_file = self.create_test_file("config.json", json_data)
        
        dependencies = self.analyzer.analyze_dependencies(test_file)
        
        # Check that file references are detected
        file_refs = [dep.get('path') for dep in dependencies if dep.get('type') == 'file_reference']
        assert '/path/to/model.pkl' in file_refs
        assert 'dataset.csv' in file_refs
        assert 'model_weights.h5' in file_refs
    
    def test_analyze_unsupported_format(self):
        """Test analysis of unsupported file format."""
        test_file = self.create_test_file("unknown.xyz", "unknown content")
        
        dependencies = self.analyzer.analyze_dependencies(test_file)
        
        # Should return empty list for unsupported formats
        assert dependencies == []
