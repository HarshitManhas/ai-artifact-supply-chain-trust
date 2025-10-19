"""
Artifact Verifier Module

Provides comprehensive verification capabilities for AI artifacts including
hash verification, signature validation, and SBOM integrity checking.
"""

import os
import json
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Union
from pathlib import Path

# Import from other modules
import sys
sys.path.append(str(Path(__file__).parent.parent))

from artifact_creation.sbom_generator import SBOMGenerator, SBOMEntry
from signing.signature_verifier import SignatureVerifier, VerificationResult
from signing.artifact_signer import SignedSBOM


class VerificationStatus:
    """Represents the verification status of an artifact."""
    
    def __init__(self, 
                 artifact_path: str,
                 is_valid: bool,
                 checks_performed: List[str],
                 messages: List[str],
                 sbom_info: Optional[Dict[str, Any]] = None,
                 signature_info: Optional[Dict[str, Any]] = None):
        self.artifact_path = artifact_path
        self.is_valid = is_valid
        self.checks_performed = checks_performed
        self.messages = messages
        self.sbom_info = sbom_info
        self.signature_info = signature_info
        self.verified_at = datetime.now(timezone.utc).isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert verification status to dictionary format."""
        return {
            'artifact_path': self.artifact_path,
            'is_valid': self.is_valid,
            'checks_performed': self.checks_performed,
            'messages': self.messages,
            'sbom_info': self.sbom_info,
            'signature_info': self.signature_info,
            'verified_at': self.verified_at
        }


class ArtifactVerifier:
    """Comprehensive artifact verification system."""
    
    def __init__(self):
        self.sbom_generator = SBOMGenerator()
        self.signature_verifier = SignatureVerifier()
    
    def verify_artifact_integrity(self, 
                                artifact_path: str, 
                                sbom_entry: Union[SBOMEntry, Dict[str, Any]]) -> VerificationStatus:
        """
        Verify artifact integrity against its SBOM entry.
        
        Args:
            artifact_path: Path to the artifact to verify
            sbom_entry: SBOM entry to verify against
            
        Returns:
            VerificationStatus object
        """
        checks_performed = ["hash_verification"]
        messages = []
        
        try:
            if not os.path.exists(artifact_path):
                return VerificationStatus(
                    artifact_path=artifact_path,
                    is_valid=False,
                    checks_performed=checks_performed,
                    messages=[f"Artifact not found: {artifact_path}"]
                )
            
            # Extract hash from SBOM entry
            if hasattr(sbom_entry, 'artifact_hash'):
                expected_hash = sbom_entry.artifact_hash
                sbom_data = sbom_entry.to_dict()
            else:
                expected_hash = sbom_entry.get('artifact_hash')
                sbom_data = sbom_entry
            
            if not expected_hash:
                return VerificationStatus(
                    artifact_path=artifact_path,
                    is_valid=False,
                    checks_performed=checks_performed,
                    messages=["No hash found in SBOM entry"]
                )
            
            # Calculate current hash
            current_hash = self.sbom_generator.calculate_hash(artifact_path)
            
            # Compare hashes
            is_valid = current_hash == expected_hash
            
            if is_valid:
                messages.append("Hash verification successful")
            else:
                messages.append(f"Hash mismatch - Expected: {expected_hash[:16]}..., Got: {current_hash[:16]}...")
            
            return VerificationStatus(
                artifact_path=artifact_path,
                is_valid=is_valid,
                checks_performed=checks_performed,
                messages=messages,
                sbom_info={
                    'sbom_id': sbom_data.get('sbom_id'),
                    'expected_hash': expected_hash,
                    'current_hash': current_hash
                }
            )
            
        except Exception as e:
            return VerificationStatus(
                artifact_path=artifact_path,
                is_valid=False,
                checks_performed=checks_performed,
                messages=[f"Verification error: {str(e)}"]
            )
    
    def verify_signed_artifact(self, 
                             artifact_path: str, 
                             signed_sbom: Union[SignedSBOM, Dict[str, Any]]) -> VerificationStatus:
        """
        Verify artifact using signed SBOM.
        
        Args:
            artifact_path: Path to the artifact to verify
            signed_sbom: Signed SBOM to verify against
            
        Returns:
            VerificationStatus object
        """
        checks_performed = ["signature_verification", "hash_verification"]
        messages = []
        
        try:
            # First verify the signature
            sig_result = self.signature_verifier.verify_signed_sbom(signed_sbom)
            
            if not sig_result.is_valid:
                return VerificationStatus(
                    artifact_path=artifact_path,
                    is_valid=False,
                    checks_performed=["signature_verification"],
                    messages=[f"Signature verification failed: {sig_result.message}"],
                    signature_info=sig_result.to_dict()
                )
            
            messages.append("Signature verification successful")
            
            # Extract SBOM data
            if hasattr(signed_sbom, 'sbom_data'):
                sbom_data = signed_sbom.sbom_data
            else:
                sbom_data = signed_sbom.get('sbom_data', {})
            
            # Verify artifact integrity
            integrity_result = self.verify_artifact_integrity(artifact_path, sbom_data)
            
            # Combine results
            messages.extend(integrity_result.messages)
            is_valid = sig_result.is_valid and integrity_result.is_valid
            
            return VerificationStatus(
                artifact_path=artifact_path,
                is_valid=is_valid,
                checks_performed=checks_performed,
                messages=messages,
                sbom_info=integrity_result.sbom_info,
                signature_info=sig_result.to_dict()
            )
            
        except Exception as e:
            return VerificationStatus(
                artifact_path=artifact_path,
                is_valid=False,
                checks_performed=checks_performed,
                messages=[f"Verification error: {str(e)}"]
            )
    
    def verify_artifact_from_file(self, 
                                artifact_path: str, 
                                sbom_file_path: str,
                                is_signed: bool = True) -> VerificationStatus:
        """
        Verify artifact using SBOM file.
        
        Args:
            artifact_path: Path to the artifact to verify
            sbom_file_path: Path to the SBOM file
            is_signed: Whether the SBOM is digitally signed
            
        Returns:
            VerificationStatus object
        """
        try:
            if not os.path.exists(sbom_file_path):
                return VerificationStatus(
                    artifact_path=artifact_path,
                    is_valid=False,
                    checks_performed=["file_check"],
                    messages=[f"SBOM file not found: {sbom_file_path}"]
                )
            
            with open(sbom_file_path, 'r') as f:
                sbom_data = json.load(f)
            
            if is_signed:
                # Verify as signed SBOM
                return self.verify_signed_artifact(artifact_path, sbom_data)
            else:
                # Verify as regular SBOM
                return self.verify_artifact_integrity(artifact_path, sbom_data)
                
        except Exception as e:
            return VerificationStatus(
                artifact_path=artifact_path,
                is_valid=False,
                checks_performed=["file_loading"],
                messages=[f"Error loading SBOM file: {str(e)}"]
            )
    
    def verify_multiple_artifacts(self, 
                                artifacts_and_sboms: List[Dict[str, str]]) -> List[VerificationStatus]:
        """
        Verify multiple artifacts with their corresponding SBOMs.
        
        Args:
            artifacts_and_sboms: List of dictionaries with 'artifact_path' and 'sbom_path' keys
            
        Returns:
            List of VerificationStatus objects
        """
        results = []
        
        for item in artifacts_and_sboms:
            artifact_path = item.get('artifact_path')
            sbom_path = item.get('sbom_path')
            is_signed = item.get('is_signed', True)
            
            if not artifact_path or not sbom_path:
                result = VerificationStatus(
                    artifact_path=artifact_path or "unknown",
                    is_valid=False,
                    checks_performed=["input_validation"],
                    messages=["Missing artifact_path or sbom_path"]
                )
                results.append(result)
                continue
            
            try:
                result = self.verify_artifact_from_file(artifact_path, sbom_path, is_signed)
                results.append(result)
            except Exception as e:
                result = VerificationStatus(
                    artifact_path=artifact_path,
                    is_valid=False,
                    checks_performed=["batch_verification"],
                    messages=[f"Batch verification error: {str(e)}"]
                )
                results.append(result)
        
        return results
    
    def generate_verification_report(self, 
                                   verification_results: List[VerificationStatus]) -> Dict[str, Any]:
        """
        Generate a comprehensive verification report.
        
        Args:
            verification_results: List of verification results
            
        Returns:
            Dictionary containing verification report
        """
        total = len(verification_results)
        valid = sum(1 for result in verification_results if result.is_valid)
        invalid = total - valid
        
        # Collect statistics
        checks_stats = {}
        for result in verification_results:
            for check in result.checks_performed:
                checks_stats[check] = checks_stats.get(check, 0) + 1
        
        # Collect error patterns
        error_messages = []
        for result in verification_results:
            if not result.is_valid:
                error_messages.extend(result.messages)
        
        report = {
            'summary': {
                'total_artifacts': total,
                'valid_artifacts': valid,
                'invalid_artifacts': invalid,
                'success_rate': (valid / total * 100) if total > 0 else 0,
                'generated_at': datetime.now(timezone.utc).isoformat()
            },
            'checks_performed': checks_stats,
            'detailed_results': [result.to_dict() for result in verification_results],
            'common_errors': self._analyze_error_patterns(error_messages)
        }
        
        return report
    
    def _analyze_error_patterns(self, error_messages: List[str]) -> Dict[str, int]:
        """Analyze common error patterns."""
        patterns = {
            'hash_mismatch': 0,
            'signature_failure': 0,
            'file_not_found': 0,
            'parse_error': 0,
            'other': 0
        }
        
        for msg in error_messages:
            if 'hash mismatch' in msg.lower():
                patterns['hash_mismatch'] += 1
            elif 'signature' in msg.lower() and 'fail' in msg.lower():
                patterns['signature_failure'] += 1
            elif 'not found' in msg.lower():
                patterns['file_not_found'] += 1
            elif 'parse' in msg.lower() or 'json' in msg.lower():
                patterns['parse_error'] += 1
            else:
                patterns['other'] += 1
        
        return patterns
    
    def verify_artifact(self, artifact_path: str, sbom_entry) -> bool:
        """
        Simple artifact verification that returns boolean.
        
        Args:
            artifact_path: Path to the artifact to verify
            sbom_entry: SBOM entry to verify against
            
        Returns:
            True if verification passes, False otherwise
        """
        try:
            result = self.verify_artifact_integrity(artifact_path, sbom_entry)
            return result.is_valid
        except Exception:
            return False
    
    async def verify_artifact_auto(self, artifact_path: str) -> bool:
        """
        Auto-verify artifact by finding matching SBOM.
        
        Args:
            artifact_path: Path to the artifact to verify
            
        Returns:
            True if verification passes, False otherwise
        """
        # This is a placeholder - in a real implementation,
        # you'd query the registry to find matching SBOMs
        try:
            # Calculate hash and check against known SBOMs
            current_hash = self.sbom_generator.calculate_hash(artifact_path)
            # For now, just return False since we don't have registry integration here
            return False
        except Exception:
            return False
    
    def save_verification_report(self, 
                               verification_results: List[VerificationStatus],
                               output_path: str) -> None:
        """
        Save verification report to file.
        
        Args:
            verification_results: List of verification results
            output_path: Path where to save the report
        """
        report = self.generate_verification_report(verification_results)
        
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
