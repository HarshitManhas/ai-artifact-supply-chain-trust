"""
Artifact Signer Module

Provides digital signing capabilities for AI artifact SBOM entries using
RSA and ECDSA cryptographic algorithms.
"""

import json
import base64
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Union
from pathlib import Path

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

from .key_manager import KeyManager


class SignedSBOM:
    """Represents a digitally signed SBOM entry."""
    
    def __init__(self, 
                 sbom_data: Dict[str, Any],
                 signature: str,
                 public_key_pem: str,
                 algorithm: str,
                 signer_info: Optional[Dict[str, Any]] = None):
        self.sbom_data = sbom_data
        self.signature = signature
        self.public_key_pem = public_key_pem
        self.algorithm = algorithm
        self.signer_info = signer_info or {}
        self.signed_at = datetime.now(timezone.utc).isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert signed SBOM to dictionary format."""
        return {
            'sbom_data': self.sbom_data,
            'signature': self.signature,
            'public_key_pem': self.public_key_pem,
            'algorithm': self.algorithm,
            'signer_info': self.signer_info,
            'signed_at': self.signed_at
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Convert signed SBOM to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


class ArtifactSigner:
    """Digital signer for AI artifact SBOM entries."""
    
    def __init__(self, 
                 private_key_path: Optional[str] = None,
                 private_key: Optional[Union[RSAPrivateKey, EllipticCurvePrivateKey]] = None,
                 algorithm: str = 'RSA-PSS',
                 signer_info: Optional[Dict[str, Any]] = None):
        """
        Initialize the artifact signer.
        
        Args:
            private_key_path: Path to private key file (PEM format)
            private_key: Pre-loaded private key object
            algorithm: Signing algorithm ('RSA-PSS', 'RSA-PKCS1v15', 'ECDSA')
            signer_info: Optional information about the signer
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            raise ImportError("cryptography library is required for signing operations")
        
        self.key_manager = KeyManager()
        self.algorithm = algorithm
        self.signer_info = signer_info or {}
        
        if private_key is not None:
            self.private_key = private_key
        elif private_key_path is not None:
            self.private_key = self.key_manager.load_private_key(private_key_path)
        else:
            raise ValueError("Either private_key_path or private_key must be provided")
        
        # Validate algorithm compatibility with key type
        self._validate_algorithm_compatibility()
    
    def _validate_algorithm_compatibility(self):
        """Validate that the algorithm is compatible with the key type."""
        if isinstance(self.private_key, RSAPrivateKey):
            if self.algorithm not in ['RSA-PSS', 'RSA-PKCS1v15']:
                raise ValueError(f"Algorithm {self.algorithm} not compatible with RSA key")
        elif isinstance(self.private_key, EllipticCurvePrivateKey):
            if self.algorithm != 'ECDSA':
                raise ValueError(f"Algorithm {self.algorithm} not compatible with EC key")
        else:
            raise ValueError(f"Unsupported key type: {type(self.private_key)}")
    
    def sign_sbom(self, sbom_entry) -> SignedSBOM:
        """
        Sign an SBOM entry.
        
        Args:
            sbom_entry: SBOM entry object or dictionary
            
        Returns:
            SignedSBOM object containing the signature and metadata
        """
        # Convert SBOM entry to dictionary if it's an object
        if hasattr(sbom_entry, 'to_dict'):
            sbom_data = sbom_entry.to_dict()
        else:
            sbom_data = sbom_entry
        
        # Serialize SBOM data for signing (ensure deterministic ordering)
        sbom_json = json.dumps(sbom_data, sort_keys=True, separators=(',', ':'))
        sbom_bytes = sbom_json.encode('utf-8')
        
        # Generate signature
        signature_bytes = self._sign_data(sbom_bytes)
        signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')
        
        # Get public key in PEM format
        public_key_pem = self._get_public_key_pem()
        
        return SignedSBOM(
            sbom_data=sbom_data,
            signature=signature_b64,
            public_key_pem=public_key_pem,
            algorithm=self.algorithm,
            signer_info=self.signer_info
        )
    
    def _sign_data(self, data: bytes) -> bytes:
        """Sign raw data using the configured algorithm."""
        if isinstance(self.private_key, RSAPrivateKey):
            return self._sign_with_rsa(data)
        elif isinstance(self.private_key, EllipticCurvePrivateKey):
            return self._sign_with_ecdsa(data)
        else:
            raise ValueError(f"Unsupported key type: {type(self.private_key)}")
    
    def _sign_with_rsa(self, data: bytes) -> bytes:
        """Sign data using RSA algorithm."""
        if self.algorithm == 'RSA-PSS':
            signature = self.private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        elif self.algorithm == 'RSA-PKCS1v15':
            signature = self.private_key.sign(
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        else:
            raise ValueError(f"Unsupported RSA algorithm: {self.algorithm}")
        
        return signature
    
    def _sign_with_ecdsa(self, data: bytes) -> bytes:
        """Sign data using ECDSA algorithm."""
        if self.algorithm == 'ECDSA':
            signature = self.private_key.sign(
                data,
                ec.ECDSA(hashes.SHA256())
            )
        else:
            raise ValueError(f"Unsupported ECDSA algorithm: {self.algorithm}")
        
        return signature
    
    def _get_public_key_pem(self) -> str:
        """Get the public key in PEM format."""
        public_key = self.private_key.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_key_pem.decode('utf-8')
    
    def sign_multiple_sboms(self, sbom_entries: list) -> list:
        """
        Sign multiple SBOM entries.
        
        Args:
            sbom_entries: List of SBOM entry objects or dictionaries
            
        Returns:
            List of SignedSBOM objects
        """
        signed_sboms = []
        
        for sbom_entry in sbom_entries:
            try:
                signed_sbom = self.sign_sbom(sbom_entry)
                signed_sboms.append(signed_sbom)
            except Exception as e:
                # Log error but continue with other entries
                print(f"Warning: Failed to sign SBOM entry: {e}")
                continue
        
        return signed_sboms
    
    def save_signed_sbom(self, signed_sbom: SignedSBOM, output_path: str) -> None:
        """
        Save a signed SBOM to a JSON file.
        
        Args:
            signed_sbom: Signed SBOM to save
            output_path: Path where to save the signed SBOM file
        """
        output_dir = Path(output_path).parent
        output_dir.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            f.write(signed_sbom.to_json())
    
    @staticmethod
    def load_signed_sbom(sbom_path: str) -> SignedSBOM:
        """
        Load a signed SBOM from a JSON file.
        
        Args:
            sbom_path: Path to the signed SBOM JSON file
            
        Returns:
            SignedSBOM object
        """
        if not Path(sbom_path).exists():
            raise FileNotFoundError(f"Signed SBOM file not found: {sbom_path}")
        
        with open(sbom_path, 'r') as f:
            data = json.load(f)
        
        return SignedSBOM(
            sbom_data=data['sbom_data'],
            signature=data['signature'],
            public_key_pem=data['public_key_pem'],
            algorithm=data['algorithm'],
            signer_info=data.get('signer_info', {})
        )
    
    def get_signer_identity(self) -> Dict[str, Any]:
        """Get information about the signer and signing setup."""
        public_key = self.private_key.public_key()
        
        identity = {
            'algorithm': self.algorithm,
            'key_type': type(self.private_key).__name__,
            'signer_info': self.signer_info,
            'public_key_fingerprint': self._calculate_public_key_fingerprint()
        }
        
        if isinstance(self.private_key, RSAPrivateKey):
            identity['key_size'] = self.private_key.key_size
        elif isinstance(self.private_key, EllipticCurvePrivateKey):
            identity['curve'] = self.private_key.curve.name
        
        return identity
    
    def _calculate_public_key_fingerprint(self) -> str:
        """Calculate fingerprint of the public key."""
        public_key_pem = self._get_public_key_pem()
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(public_key_pem.encode('utf-8'))
        fingerprint = digest.finalize()
        return base64.b64encode(fingerprint).decode('utf-8')[:32]
