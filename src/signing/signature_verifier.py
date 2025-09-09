"""
Signature Verifier Module

Verifies digital signatures on SBOM entries to ensure authenticity and integrity.
"""

import json
import base64
from typing import Dict, Any, Union, Optional

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
    from cryptography.exceptions import InvalidSignature
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

from .key_manager import KeyManager


class VerificationResult:
    """Result of signature verification operation."""
    
    def __init__(self, 
                 is_valid: bool,
                 message: str = "",
                 public_key_info: Optional[Dict[str, Any]] = None,
                 algorithm: Optional[str] = None):
        self.is_valid = is_valid
        self.message = message
        self.public_key_info = public_key_info
        self.algorithm = algorithm
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert verification result to dictionary."""
        return {
            'is_valid': self.is_valid,
            'message': self.message,
            'public_key_info': self.public_key_info,
            'algorithm': self.algorithm
        }


class SignatureVerifier:
    """Verifies digital signatures on SBOM entries."""
    
    def __init__(self):
        if not CRYPTOGRAPHY_AVAILABLE:
            raise ImportError("cryptography library is required for signature verification")
        
        self.key_manager = KeyManager()
    
    def verify_signed_sbom(self, signed_sbom) -> VerificationResult:
        """
        Verify a signed SBOM entry.
        
        Args:
            signed_sbom: SignedSBOM object or dictionary containing signed SBOM data
            
        Returns:
            VerificationResult object
        """
        try:
            # Extract data from signed SBOM
            if hasattr(signed_sbom, 'to_dict'):
                signed_data = signed_sbom.to_dict()
            else:
                signed_data = signed_sbom
            
            sbom_data = signed_data['sbom_data']
            signature_b64 = signed_data['signature']
            public_key_pem = signed_data['public_key_pem']
            algorithm = signed_data['algorithm']
            
            # Load public key
            public_key = self.key_manager.load_public_key_from_string(public_key_pem)
            
            # Recreate the exact data that was signed
            sbom_json = json.dumps(sbom_data, sort_keys=True, separators=(',', ':'))
            sbom_bytes = sbom_json.encode('utf-8')
            
            # Decode signature
            signature_bytes = base64.b64decode(signature_b64)
            
            # Verify signature
            is_valid = self._verify_signature(
                data=sbom_bytes,
                signature=signature_bytes,
                public_key=public_key,
                algorithm=algorithm
            )
            
            # Get public key info
            public_key_info = self.key_manager.get_key_info(public_key)
            
            if is_valid:
                return VerificationResult(
                    is_valid=True,
                    message="Signature verification successful",
                    public_key_info=public_key_info,
                    algorithm=algorithm
                )
            else:
                return VerificationResult(
                    is_valid=False,
                    message="Signature verification failed",
                    public_key_info=public_key_info,
                    algorithm=algorithm
                )
        
        except Exception as e:
            return VerificationResult(
                is_valid=False,
                message=f"Verification error: {str(e)}"
            )
    
    def _verify_signature(self, 
                         data: bytes,
                         signature: bytes,
                         public_key: Union[RSAPublicKey, EllipticCurvePublicKey],
                         algorithm: str) -> bool:
        """
        Verify a signature using the specified algorithm.
        
        Args:
            data: Original data that was signed
            signature: Signature bytes to verify
            public_key: Public key for verification
            algorithm: Signature algorithm used
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            if isinstance(public_key, RSAPublicKey):
                return self._verify_rsa_signature(data, signature, public_key, algorithm)
            elif isinstance(public_key, EllipticCurvePublicKey):
                return self._verify_ecdsa_signature(data, signature, public_key, algorithm)
            else:
                raise ValueError(f"Unsupported public key type: {type(public_key)}")
        
        except InvalidSignature:
            return False
        except Exception:
            return False
    
    def _verify_rsa_signature(self, 
                             data: bytes,
                             signature: bytes,
                             public_key: RSAPublicKey,
                             algorithm: str) -> bool:
        """Verify RSA signature."""
        if algorithm == 'RSA-PSS':
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        elif algorithm == 'RSA-PKCS1v15':
            public_key.verify(
                signature,
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        else:
            raise ValueError(f"Unsupported RSA algorithm: {algorithm}")
        
        return True
    
    def _verify_ecdsa_signature(self, 
                               data: bytes,
                               signature: bytes,
                               public_key: EllipticCurvePublicKey,
                               algorithm: str) -> bool:
        """Verify ECDSA signature."""
        if algorithm == 'ECDSA':
            public_key.verify(
                signature,
                data,
                ec.ECDSA(hashes.SHA256())
            )
        else:
            raise ValueError(f"Unsupported ECDSA algorithm: {algorithm}")
        
        return True
    
    def verify_with_public_key_file(self, 
                                   signed_sbom,
                                   public_key_path: str) -> VerificationResult:
        """
        Verify a signed SBOM using a public key file.
        
        Args:
            signed_sbom: SignedSBOM object or dictionary
            public_key_path: Path to public key file
            
        Returns:
            VerificationResult object
        """
        try:
            # Load public key from file
            public_key = self.key_manager.load_public_key(public_key_path)
            
            # Extract signed data
            if hasattr(signed_sbom, 'to_dict'):
                signed_data = signed_sbom.to_dict()
            else:
                signed_data = signed_sbom
            
            sbom_data = signed_data['sbom_data']
            signature_b64 = signed_data['signature']
            algorithm = signed_data['algorithm']
            
            # Recreate the exact data that was signed
            sbom_json = json.dumps(sbom_data, sort_keys=True, separators=(',', ':'))
            sbom_bytes = sbom_json.encode('utf-8')
            
            # Decode signature
            signature_bytes = base64.b64decode(signature_b64)
            
            # Verify signature
            is_valid = self._verify_signature(
                data=sbom_bytes,
                signature=signature_bytes,
                public_key=public_key,
                algorithm=algorithm
            )
            
            # Get public key info
            public_key_info = self.key_manager.get_key_info(public_key)
            
            if is_valid:
                return VerificationResult(
                    is_valid=True,
                    message="Signature verification successful with provided public key",
                    public_key_info=public_key_info,
                    algorithm=algorithm
                )
            else:
                return VerificationResult(
                    is_valid=False,
                    message="Signature verification failed with provided public key",
                    public_key_info=public_key_info,
                    algorithm=algorithm
                )
        
        except Exception as e:
            return VerificationResult(
                is_valid=False,
                message=f"Verification error with public key file: {str(e)}"
            )
    
    def verify_multiple_signed_sboms(self, signed_sboms: list) -> list:
        """
        Verify multiple signed SBOM entries.
        
        Args:
            signed_sboms: List of SignedSBOM objects or dictionaries
            
        Returns:
            List of VerificationResult objects
        """
        results = []
        
        for signed_sbom in signed_sboms:
            result = self.verify_signed_sbom(signed_sbom)
            results.append(result)
        
        return results
    
    def get_verification_summary(self, verification_results: list) -> Dict[str, Any]:
        """
        Generate a summary of verification results.
        
        Args:
            verification_results: List of VerificationResult objects
            
        Returns:
            Dictionary containing verification summary
        """
        total = len(verification_results)
        valid = sum(1 for result in verification_results if result.is_valid)
        invalid = total - valid
        
        # Collect unique algorithms and key types
        algorithms = set()
        key_types = set()
        
        for result in verification_results:
            if result.algorithm:
                algorithms.add(result.algorithm)
            if result.public_key_info and 'algorithm' in result.public_key_info:
                key_types.add(result.public_key_info['algorithm'])
        
        return {
            'total_verified': total,
            'valid_signatures': valid,
            'invalid_signatures': invalid,
            'success_rate': (valid / total * 100) if total > 0 else 0,
            'algorithms_used': list(algorithms),
            'key_types_used': list(key_types)
        }
