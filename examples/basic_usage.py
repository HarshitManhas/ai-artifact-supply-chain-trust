#!/usr/bin/env python3
"""
Basic Usage Example for AI Artifact Supply Chain Trust Framework

This example demonstrates the core functionality:
1. Creating SBOM entries for AI artifacts
2. Digitally signing SBOM entries
3. Verifying signed SBOM entries
4. Storing and retrieving SBOMs
"""

import os
import sys
import tempfile
import pickle
from pathlib import Path

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from artifact_creation import SBOMGenerator
from signing import ArtifactSigner, KeyManager, SignatureVerifier


def create_sample_artifacts():
    """Create sample AI artifacts for demonstration."""
    print("📦 Creating sample AI artifacts...")
    
    # Create a sample model (pickle file)
    sample_data = {
        'model_type': 'logistic_regression',
        'version': '1.0.0',
        'parameters': [0.5, -0.3, 0.8, 0.2],
        'accuracy': 0.94
    }
    
    model_path = "examples/artifacts/sample_model.pkl"
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    
    with open(model_path, 'wb') as f:
        pickle.dump(sample_data, f)
    
    # Create a sample configuration file
    config_path = "examples/artifacts/sample_config.json"
    import json
    config_data = {
        "model_name": "sample_classifier",
        "training_data": "customer_dataset_v2.csv",
        "hyperparameters": {
            "learning_rate": 0.01,
            "epochs": 100,
            "batch_size": 32
        }
    }
    
    with open(config_path, 'w') as f:
        json.dump(config_data, f, indent=2)
    
    print(f"✅ Created sample model: {model_path}")
    print(f"✅ Created sample config: {config_path}")
    
    return model_path, config_path


def demonstrate_sbom_generation():
    """Demonstrate SBOM generation for AI artifacts."""
    print("\n🔍 Generating SBOM entries...")
    
    # Create sample artifacts
    model_path, config_path = create_sample_artifacts()
    
    # Initialize SBOM generator
    generator = SBOMGenerator()
    
    # Generate SBOM for the model
    print(f"Generating SBOM for: {model_path}")
    model_sbom = generator.create_sbom(
        artifact_path=model_path,
        additional_metadata={
            'creator': 'ai-trust-demo',
            'purpose': 'demonstration',
            'classification': 'public'
        }
    )
    
    print(f"✅ Model SBOM ID: {model_sbom.sbom_id}")
    print(f"   Hash: {model_sbom.artifact_hash[:16]}...")
    
    # Generate SBOM for the config
    print(f"Generating SBOM for: {config_path}")
    config_sbom = generator.create_sbom(config_path)
    
    print(f"✅ Config SBOM ID: {config_sbom.sbom_id}")
    print(f"   Hash: {config_sbom.artifact_hash[:16]}...")
    
    return model_sbom, config_sbom


def demonstrate_signing():
    """Demonstrate digital signing of SBOM entries."""
    print("\n🔐 Signing SBOM entries...")
    
    # Generate SBOMs
    model_sbom, config_sbom = demonstrate_sbom_generation()
    
    # Set up key manager and generate keys
    key_manager = KeyManager()
    
    # Create temporary keys for demo
    with tempfile.TemporaryDirectory() as temp_dir:
        private_key_path = os.path.join(temp_dir, "demo_private.pem")
        public_key_path = os.path.join(temp_dir, "demo_public.pem")
        
        # Generate RSA key pair
        private_key, public_key = key_manager.generate_rsa_key_pair(key_size=2048)
        key_manager.save_private_key(private_key, private_key_path)
        key_manager.save_public_key(public_key, public_key_path)
        
        print(f"✅ Generated temporary RSA key pair")
        
        # Initialize signer
        signer = ArtifactSigner(
            private_key_path=private_key_path,
            algorithm='RSA-PSS',
            signer_info={
                'organization': 'AI Trust Demo',
                'email': 'demo@ai-trust.example',
                'purpose': 'demonstration'
            }
        )
        
        # Sign the SBOMs
        signed_model_sbom = signer.sign_sbom(model_sbom)
        signed_config_sbom = signer.sign_sbom(config_sbom)
        
        print(f"✅ Signed model SBOM")
        print(f"   Algorithm: {signed_model_sbom.algorithm}")
        print(f"   Signature: {signed_model_sbom.signature[:32]}...")
        
        print(f"✅ Signed config SBOM")
        print(f"   Algorithm: {signed_config_sbom.algorithm}")
        
        return signed_model_sbom, signed_config_sbom, public_key_path


def demonstrate_verification():
    """Demonstrate verification of signed SBOM entries."""
    print("\n✅ Verifying signed SBOM entries...")
    
    # Get signed SBOMs
    signed_model_sbom, signed_config_sbom, public_key_path = demonstrate_signing()
    
    # Initialize verifier
    verifier = SignatureVerifier()
    
    # Verify the signatures
    model_result = verifier.verify_signed_sbom(signed_model_sbom)
    config_result = verifier.verify_signed_sbom(signed_config_sbom)
    
    print(f"Model SBOM verification: {'✅ VALID' if model_result.is_valid else '❌ INVALID'}")
    print(f"  Message: {model_result.message}")
    if model_result.public_key_info:
        print(f"  Key type: {model_result.public_key_info.get('algorithm', 'unknown')}")
        print(f"  Key size: {model_result.public_key_info.get('key_size', 'unknown')} bits")
    
    print(f"Config SBOM verification: {'✅ VALID' if config_result.is_valid else '❌ INVALID'}")
    print(f"  Message: {config_result.message}")
    
    # Test verification with external public key file
    print("\n🔍 Testing verification with external public key...")
    external_result = verifier.verify_with_public_key_file(signed_model_sbom, public_key_path)
    print(f"External key verification: {'✅ VALID' if external_result.is_valid else '❌ INVALID'}")
    
    return [model_result, config_result, external_result]


def demonstrate_persistence():
    """Demonstrate saving and loading of signed SBOMs."""
    print("\n💾 Demonstrating SBOM persistence...")
    
    # Get a signed SBOM
    signed_model_sbom, _, _ = demonstrate_signing()
    
    # Save to file
    output_path = "examples/output/signed_model_sbom.json"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Use the signer class method to save
    ArtifactSigner.save_signed_sbom(signed_model_sbom, output_path)
    print(f"✅ Saved signed SBOM to: {output_path}")
    
    # Load from file
    loaded_sbom = ArtifactSigner.load_signed_sbom(output_path)
    print(f"✅ Loaded signed SBOM from file")
    print(f"   SBOM ID: {loaded_sbom.sbom_data.get('sbom_id', 'unknown')}")
    
    # Verify the loaded SBOM
    verifier = SignatureVerifier()
    loaded_result = verifier.verify_signed_sbom(loaded_sbom)
    print(f"   Verification: {'✅ VALID' if loaded_result.is_valid else '❌ INVALID'}")
    
    return output_path


def generate_summary_report():
    """Generate a summary report of the demonstration."""
    print("\n📊 Running complete demonstration and generating report...")
    
    # Run all demonstrations
    verification_results = demonstrate_verification()
    saved_path = demonstrate_persistence()
    
    # Generate summary
    total_verifications = len(verification_results)
    valid_verifications = sum(1 for r in verification_results if r.is_valid)
    
    print("\n" + "="*60)
    print("🎉 AI ARTIFACT SUPPLY CHAIN TRUST FRAMEWORK DEMO COMPLETE")
    print("="*60)
    print(f"✅ Artifacts processed: 2 (model + config)")
    print(f"✅ SBOMs generated: 2")
    print(f"✅ Digital signatures created: 2")
    print(f"✅ Verification attempts: {total_verifications}")
    print(f"✅ Successful verifications: {valid_verifications}/{total_verifications}")
    print(f"✅ SBOM saved to: {saved_path}")
    print()
    print("🔐 Security Features Demonstrated:")
    print("   • Cryptographic fingerprinting (SHA-256)")
    print("   • Digital signatures (RSA-PSS)")
    print("   • Metadata extraction and preservation")
    print("   • Signature verification and validation")
    print("   • Persistent storage and retrieval")
    print()
    print("📈 Next Steps:")
    print("   • Integrate with CI/CD pipelines")
    print("   • Deploy Kubernetes admission controllers")
    print("   • Set up centralized SBOM registry")
    print("   • Configure monitoring dashboard")
    print("="*60)


def main():
    """Run the complete basic usage demonstration."""
    print("🚀 AI Artifact Supply Chain Trust Framework - Basic Usage Demo")
    print("="*70)
    
    try:
        # Check if we're in the right directory
        if not os.path.exists("src/artifact_creation"):
            print("❌ Error: Please run this script from the project root directory")
            return 1
        
        # Run the complete demonstration
        generate_summary_report()
        
        print("\n✨ Demo completed successfully!")
        return 0
        
    except ImportError as e:
        print(f"❌ Import Error: {e}")
        print("💡 Make sure to install dependencies: pip install -r requirements.txt")
        return 1
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    exit(main())
