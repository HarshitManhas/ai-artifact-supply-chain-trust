# AI Artifact Supply Chain Trust Framework

A comprehensive cybersecurity framework that provides end-to-end integrity, authenticity, and provenance guarantees for AI artifacts through SBOM principles, cryptographic signing, vulnerability scanning, and enforcement mechanisms.

## 🎯 Objective

To secure the AI supply chain by ensuring that all AI artifacts (datasets, model weights, configuration files, preprocessing scripts, dependencies) are:
- **Authentic**: Verified to come from trusted sources
- **Integral**: Guaranteed to be unmodified since creation
- **Traceable**: Full provenance tracking throughout the lifecycle
- **Compliant**: Automatically enforced in CI/CD and deployment pipelines

## 🏗️ Architecture Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  AI Artifacts   │───▶│  SBOM Creation   │───▶│  Cryptographic  │
│                 │    │   & Metadata     │    │    Signing      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                         │
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Dashboard &   │◀───│  SBOM Registry   │◀───│   Signed SBOM   │
│  Visualization  │    │    Storage       │    │    Storage      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         ▲                       ▲                       │
         │               ┌──────────────────┐            │
         └───────────────│  Verification &  │◀───────────┘
                         │   Validation     │
                         └──────────────────┘
                                  │
                         ┌──────────────────┐
                         │   Enforcement    │
                         │ (CI/CD + K8s)    │
                         └──────────────────┘
```

## 🔄 Conceptual Flow

### 1. Artifact Creation
- **Input**: AI artifacts (datasets, models, scripts, configs)
- **Process**: 
  - Generate cryptographic fingerprints (SHA-256)
  - Extract metadata (origin, version, creator, timestamp)
  - Create SBOM entry
- **Output**: `{artifact + hash + metadata}`

### 2. Artifact Signing
- **Process**: Digital signing with private keys
- **Purpose**: Ensures authenticity from trusted sources
- **Result**: Tamper-proof artifact identity

### 3. SBOM Storage
- **Storage**: Secure registry (local, cloud, IPFS)
- **Access**: Public verification capability
- **Function**: Acts as artifact "passport"

### 4. Verification at Usage
- **Trigger**: Training, deployment, fine-tuning, sharing
- **Process**: 
  - Recalculate artifact hash
  - Verify signature against SBOM
  - Flag mismatches as tampered/untrusted
- **Result**: Only verified artifacts proceed

### 5. Enforcement
- **Integration**: CI/CD pipelines, Kubernetes admission controllers
- **Action**: Block unverified artifacts automatically
- **Benefit**: Prevent malicious components reaching production

### 6. Auditing & Visualization
- **Dashboard**: Neo4j + React visualization
- **Features**: 
  - Provenance chain tracking
  - Integrity status monitoring
  - Dependency trust levels
  - Full supply chain visibility

## 📁 Project Structure

```
ai-artifact-supply-chain-trust/
├── src/
│   ├── artifact_creation/     # SBOM generation and metadata extraction
│   ├── signing/              # Cryptographic signing system
│   ├── sbom_storage/         # Registry and storage mechanisms
│   ├── verification/         # Hash verification and signature validation
│   └── enforcement/          # CI/CD and Kubernetes integrations
│       ├── cicd/            # CI/CD pipeline integrations
│       └── kubernetes/      # K8s admission controllers
├── dashboard/
│   ├── frontend/            # React-based visualization dashboard
│   └── backend/             # Neo4j backend and APIs
├── docs/                    # Detailed documentation
├── tests/                   # Unit and integration tests
├── examples/               # Usage examples and demos
├── scripts/                # Setup and utility scripts
└── config/                 # Configuration templates
```

## 🚀 Getting Started

### Prerequisites
- Python 3.8+
- Node.js 16+
- Docker (for containerized deployment)
- Neo4j (for dashboard backend)

### Quick Setup
```bash
# Clone the repository
git clone <repository-url>
cd ai-artifact-supply-chain-trust

# Install Python dependencies
pip install -r requirements.txt

# Install Node.js dependencies for dashboard
cd dashboard/frontend && npm install
cd ../backend && npm install

# Run setup script
./scripts/setup.sh
```

## 🔧 Core Components

### Artifact Creation & SBOM Generation
Creates cryptographic fingerprints and metadata for AI artifacts:
```python
from src.artifact_creation import SBOMGenerator

generator = SBOMGenerator()
sbom_entry = generator.create_sbom(artifact_path="model.pkl")
```

### Cryptographic Signing
Signs SBOM entries for authenticity:
```python
from src.signing import ArtifactSigner

signer = ArtifactSigner(private_key_path="keys/private.pem")
signed_sbom = signer.sign_sbom(sbom_entry)
```

### Verification System
Validates artifacts before usage:
```python
from src.verification import ArtifactVerifier

verifier = ArtifactVerifier()
is_valid = verifier.verify_artifact("model.pkl", signed_sbom)
```

### Enforcement Integration
Kubernetes admission controller example:
```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionWebhook
metadata:
  name: ai-artifact-verifier
spec:
  clientConfig:
    service:
      name: artifact-verification-service
```

## 🛡️ Security Model

### Threat Model
- **Supply Chain Attacks**: Malicious artifact injection
- **Data Poisoning**: Compromised training datasets
- **Model Tampering**: Unauthorized model modifications
- **Dependency Confusion**: Malicious dependency substitution

### Security Guarantees
- **Cryptographic Integrity**: SHA-256 hashing
- **Digital Authentication**: RSA/ECDSA signatures
- **Non-Repudiation**: Immutable audit trail
- **Access Control**: Role-based permissions

## 📊 Dashboard Features

### Provenance Visualization
- Artifact lineage graphs
- Dependency relationship mapping
- Trust score visualization

### Security Status
- Real-time integrity monitoring
- Vulnerability scanning results
- Compliance status tracking

### Audit Trails
- Complete artifact lifecycle logs
- Signature verification history
- Access and usage patterns

## 🏭 Enterprise Integration

### CI/CD Pipeline Integration
- GitHub Actions workflows
- Jenkins pipeline plugins
- GitLab CI integration
- Azure DevOps extensions

### Container Registry Support
- Docker Hub integration
- AWS ECR compatibility
- Azure Container Registry
- Google Container Registry

### Cloud Platform Support
- AWS S3 storage backend
- Azure Blob Storage
- Google Cloud Storage
- IPFS distributed storage

## 🧪 Testing

### Unit Tests
```bash
python -m pytest tests/unit/
```

### Integration Tests
```bash
python -m pytest tests/integration/
```

### End-to-End Tests
```bash
./scripts/run-e2e-tests.sh
```

## 📚 Documentation

- [Architecture Guide](docs/architecture.md)
- [API Reference](docs/api-reference.md)
- [Deployment Guide](docs/deployment.md)
- [Security Best Practices](docs/security.md)
- [Troubleshooting](docs/troubleshooting.md)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- Documentation: [docs/](docs/)
- Issues: [GitHub Issues](https://github.com/your-org/ai-artifact-supply-chain-trust/issues)
- Discussions: [GitHub Discussions](https://github.com/your-org/ai-artifact-supply-chain-trust/discussions)

## 🗺️ Roadmap

### Phase 1: Core Framework ✅
- [x] SBOM generation
- [x] Cryptographic signing
- [x] Basic verification

### Phase 2: Enterprise Integration 🚧
- [ ] Kubernetes admission controllers
- [ ] CI/CD pipeline plugins
- [ ] Cloud storage backends

### Phase 3: Advanced Features 📋
- [ ] ML-based anomaly detection
- [ ] Automated vulnerability scanning
- [ ] Zero-knowledge proofs
- [ ] Blockchain integration

---

**Built with ❤️ for AI Security**
