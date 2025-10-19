"""
Integrity Checker Module

Provides utility functions for checking integrity of AI artifacts and related files.
"""

import os
import hashlib
from typing import Dict, List, Any, Optional
from pathlib import Path


class IntegrityChecker:
    """Utility class for integrity checking operations."""
    
    @staticmethod
    def calculate_directory_hash(directory_path: str, 
                               include_patterns: Optional[List[str]] = None,
                               exclude_patterns: Optional[List[str]] = None) -> str:
        """
        Calculate hash for entire directory contents.
        
        Args:
            directory_path: Path to directory
            include_patterns: File patterns to include (e.g., ['*.pkl', '*.json'])
            exclude_patterns: File patterns to exclude
            
        Returns:
            SHA-256 hash of directory contents
        """
        if not os.path.exists(directory_path):
            raise FileNotFoundError(f"Directory not found: {directory_path}")
        
        hasher = hashlib.sha256()
        
        # Collect all files
        files_to_hash = []
        for root, dirs, files in os.walk(directory_path):
            # Sort for deterministic ordering
            dirs.sort()
            files.sort()
            
            for file in files:
                file_path = os.path.join(root, file)
                
                # Apply filters
                if include_patterns:
                    if not any(Path(file).match(pattern) for pattern in include_patterns):
                        continue
                
                if exclude_patterns:
                    if any(Path(file).match(pattern) for pattern in exclude_patterns):
                        continue
                
                files_to_hash.append(file_path)
        
        # Hash files in sorted order
        for file_path in sorted(files_to_hash):
            # Hash the relative path first
            rel_path = os.path.relpath(file_path, directory_path)
            hasher.update(rel_path.encode('utf-8'))
            
            # Then hash the file contents
            try:
                with open(file_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        hasher.update(chunk)
            except (OSError, IOError):
                # If file can't be read, hash the error indicator
                hasher.update(b"<UNREADABLE_FILE>")
        
        return hasher.hexdigest()
    
    @staticmethod
    def compare_file_hashes(file_paths: List[str]) -> Dict[str, str]:
        """
        Calculate hashes for multiple files.
        
        Args:
            file_paths: List of file paths to hash
            
        Returns:
            Dictionary mapping file paths to their hashes
        """
        hashes = {}
        
        for file_path in file_paths:
            try:
                hasher = hashlib.sha256()
                with open(file_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        hasher.update(chunk)
                hashes[file_path] = hasher.hexdigest()
            except (OSError, IOError) as e:
                hashes[file_path] = f"ERROR: {str(e)}"
        
        return hashes
    
    @staticmethod
    def verify_file_exists_and_readable(file_path: str) -> Dict[str, Any]:
        """
        Verify file exists and is readable.
        
        Args:
            file_path: Path to check
            
        Returns:
            Dictionary with verification results
        """
        result = {
            'exists': False,
            'readable': False,
            'size': 0,
            'error': None
        }
        
        try:
            if os.path.exists(file_path):
                result['exists'] = True
                result['size'] = os.path.getsize(file_path)
                
                # Try to read first few bytes
                with open(file_path, 'rb') as f:
                    f.read(1)  # Try to read one byte
                result['readable'] = True
                
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    @staticmethod
    def detect_file_changes(original_hashes: Dict[str, str], 
                          current_directory: str) -> Dict[str, Any]:
        """
        Detect changes in files by comparing hashes.
        
        Args:
            original_hashes: Dictionary of original file hashes
            current_directory: Directory to check for changes
            
        Returns:
            Dictionary with change detection results
        """
        results = {
            'changed_files': [],
            'new_files': [],
            'deleted_files': [],
            'unchanged_files': []
        }
        
        # Get current hashes
        current_files = []
        for root, dirs, files in os.walk(current_directory):
            for file in files:
                file_path = os.path.join(root, file)
                current_files.append(file_path)
        
        current_hashes = IntegrityChecker.compare_file_hashes(current_files)
        
        # Compare with original hashes
        original_paths = set(original_hashes.keys())
        current_paths = set(current_hashes.keys())
        
        # Find deleted files
        results['deleted_files'] = list(original_paths - current_paths)
        
        # Find new files
        results['new_files'] = list(current_paths - original_paths)
        
        # Check existing files for changes
        common_files = original_paths & current_paths
        for file_path in common_files:
            if original_hashes[file_path] == current_hashes[file_path]:
                results['unchanged_files'].append(file_path)
            else:
                results['changed_files'].append({
                    'file_path': file_path,
                    'original_hash': original_hashes[file_path],
                    'current_hash': current_hashes[file_path]
                })
        
        return results