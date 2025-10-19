"""
Key Manager Module

Manages cryptographic keys for signing and verification operations.
Supports RSA and ECDSA key generation, loading, and saving.
"""

import os
from pathlib import Path
from typing import Union, Optional, Tuple

try:
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False


class KeyManager:
    """Manages cryptographic keys for the signing system."""
    
    def __init__(self):
        if not CRYPTOGRAPHY_AVAILABLE:
            raise ImportError("cryptography library is required for key management operations")
    
    def generate_rsa_key_pair(self, 
                             key_size: int = 2048,
                             public_exponent: int = 65537) -> Tuple[RSAPrivateKey, RSAPublicKey]:
        """
        Generate an RSA key pair.
        
        Args:
            key_size: Key size in bits (default: 2048)
            public_exponent: Public exponent (default: 65537)
            
        Returns:
            Tuple of (private_key, public_key)
        """
        if key_size < 2048:
            raise ValueError("RSA key size must be at least 2048 bits")
        
        private_key = rsa.generate_private_key(
            public_exponent=public_exponent,
            key_size=key_size,
            backend=default_backend()
        )
        
        public_key = private_key.public_key()
        return private_key, public_key
    
    def generate_ecdsa_key_pair(self, 
                               curve_name: str = 'secp256r1') -> Tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
        """
        Generate an ECDSA key pair.
        
        Args:
            curve_name: Name of the elliptic curve (default: secp256r1)
            
        Returns:
            Tuple of (private_key, public_key)
        """
        # Map curve names to cryptography curve objects
        curve_map = {
            'secp256r1': ec.SECP256R1(),
            'secp384r1': ec.SECP384R1(),
            'secp521r1': ec.SECP521R1(),
        }
        
        if curve_name not in curve_map:
            raise ValueError(f"Unsupported curve: {curve_name}. Supported curves: {list(curve_map.keys())}")
        
        private_key = ec.generate_private_key(
            curve_map[curve_name],
            backend=default_backend()
        )
        
        public_key = private_key.public_key()
        return private_key, public_key
    
    def save_private_key(self, 
                        private_key: Union[RSAPrivateKey, EllipticCurvePrivateKey],
                        file_path: str,
                        password: Optional[bytes] = None) -> None:
        """
        Save a private key to a PEM file.
        
        Args:
            private_key: Private key to save
            file_path: Path where to save the key
            password: Optional password for encryption
        """
        # Ensure directory exists
        output_dir = Path(file_path).parent
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Configure encryption
        encryption_algorithm = serialization.NoEncryption()
        if password is not None:
            encryption_algorithm = serialization.BestAvailableEncryption(password)
        
        # Serialize private key
        pem_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        
        # Write to file with secure permissions
        with open(file_path, 'wb') as f:
            f.write(pem_bytes)
        
        # Set secure file permissions (owner read/write only)
        os.chmod(file_path, 0o600)
    
    def save_public_key(self, 
                       public_key: Union[RSAPublicKey, EllipticCurvePublicKey],
                       file_path: str) -> None:
        """
        Save a public key to a PEM file.
        
        Args:
            public_key: Public key to save
            file_path: Path where to save the key
        """
        # Ensure directory exists
        output_dir = Path(file_path).parent
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Serialize public key
        pem_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Write to file
        with open(file_path, 'wb') as f:
            f.write(pem_bytes)
    
    def load_private_key(self, 
                        file_path: str,
                        password: Optional[bytes] = None) -> Union[RSAPrivateKey, EllipticCurvePrivateKey]:
        """
        Load a private key from a PEM file.
        
        Args:
            file_path: Path to the private key file
            password: Optional password for decryption
            
        Returns:
            Private key object
        """
        if not Path(file_path).exists():
            raise FileNotFoundError(f"Private key file not found: {file_path}")
        
        with open(file_path, 'rb') as f:
            pem_data = f.read()
        
        private_key = serialization.load_pem_private_key(
            pem_data,
            password=password,
            backend=default_backend()
        )
        
        return private_key
    
    def load_public_key(self, 
                       file_path: str) -> Union[RSAPublicKey, EllipticCurvePublicKey]:
        """
        Load a public key from a PEM file.
        
        Args:
            file_path: Path to the public key file
            
        Returns:
            Public key object
        """
        if not Path(file_path).exists():
            raise FileNotFoundError(f"Public key file not found: {file_path}")
        
        with open(file_path, 'rb') as f:
            pem_data = f.read()
        
        public_key = serialization.load_pem_public_key(
            pem_data,
            backend=default_backend()
        )
        
        return public_key
    
    def load_public_key_from_string(self, 
                                   pem_string: str) -> Union[RSAPublicKey, EllipticCurvePublicKey]:
        """
        Load a public key from a PEM string.
        
        Args:
            pem_string: PEM-formatted public key string
            
        Returns:
            Public key object
        """
        pem_bytes = pem_string.encode('utf-8')
        
        public_key = serialization.load_pem_public_key(
            pem_bytes,
            backend=default_backend()
        )
        
        return public_key
    
    def create_key_pair_files(self, 
                             key_type: str = 'RSA',
                             private_key_path: str = 'private_key.pem',
                             public_key_path: str = 'public_key.pem',
                             password: Optional[bytes] = None,
                             **kwargs) -> Tuple[str, str]:
        """
        Generate and save a key pair to files.
        
        Args:
            key_type: Type of key to generate ('RSA' or 'ECDSA')
            private_key_path: Path for private key file
            public_key_path: Path for public key file
            password: Optional password for private key encryption
            **kwargs: Additional arguments for key generation
            
        Returns:
            Tuple of (private_key_path, public_key_path)
        """
        if key_type.upper() == 'RSA':
            private_key, public_key = self.generate_rsa_key_pair(**kwargs)
        elif key_type.upper() == 'ECDSA':
            private_key, public_key = self.generate_ecdsa_key_pair(**kwargs)
        else:
            raise ValueError(f"Unsupported key type: {key_type}")
        
        # Save keys to files
        self.save_private_key(private_key, private_key_path, password)
        self.save_public_key(public_key, public_key_path)
        
        return private_key_path, public_key_path
    
    def get_key_info(self, 
                    key: Union[RSAPrivateKey, RSAPublicKey, EllipticCurvePrivateKey, EllipticCurvePublicKey]) -> dict:
        """
        Get information about a cryptographic key.
        
        Args:
            key: Key object to analyze
            
        Returns:
            Dictionary containing key information
        """
        info = {
            'type': type(key).__name__,
            'is_private': isinstance(key, (RSAPrivateKey, EllipticCurvePrivateKey))
        }
        
        if isinstance(key, (RSAPrivateKey, RSAPublicKey)):
            if isinstance(key, RSAPrivateKey):
                public_key = key.public_key()
            else:
                public_key = key
            
            info.update({
                'algorithm': 'RSA',
                'key_size': public_key.key_size,
                'public_exponent': public_key.public_numbers().e
            })
        
        elif isinstance(key, (EllipticCurvePrivateKey, EllipticCurvePublicKey)):
            if isinstance(key, EllipticCurvePrivateKey):
                public_key = key.public_key()
            else:
                public_key = key
            
            info.update({
                'algorithm': 'ECDSA',
                'curve': public_key.curve.name,
                'key_size': public_key.curve.key_size
            })
        
        return info
