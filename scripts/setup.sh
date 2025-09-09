#!/bin/bash

# AI Artifact Supply Chain Trust Framework Setup Script
# This script sets up the development environment and initializes the project

set -e  # Exit on any error

echo "🚀 Setting up AI Artifact Supply Chain Trust Framework..."

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "\n${BLUE}=== $1 ===${NC}\n"
}

# Check if Python 3.8+ is installed
check_python() {
    print_header "Checking Python Installation"
    if command -v python3 &> /dev/null; then
        python_version=$(python3 --version | cut -d' ' -f2)
        print_status "Python $python_version found"
        
        # Check if version is 3.8+
        if python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
            print_status "Python version is compatible"
        else
            print_error "Python 3.8 or higher is required"
            exit 1
        fi
    else
        print_error "Python 3 is not installed"
        exit 1
    fi
}

# Check if Node.js is installed
check_nodejs() {
    print_header "Checking Node.js Installation"
    if command -v node &> /dev/null; then
        node_version=$(node --version)
        print_status "Node.js $node_version found"
        
        # Check if npm is available
        if command -v npm &> /dev/null; then
            npm_version=$(npm --version)
            print_status "npm $npm_version found"
        else
            print_error "npm is not installed"
            exit 1
        fi
    else
        print_error "Node.js is not installed"
        print_status "Please install Node.js 16+ from https://nodejs.org/"
        exit 1
    fi
}

# Setup Python virtual environment
setup_python_env() {
    print_header "Setting up Python Environment"
    
    if [ ! -d "venv" ]; then
        print_status "Creating virtual environment..."
        python3 -m venv venv
    else
        print_status "Virtual environment already exists"
    fi
    
    print_status "Activating virtual environment..."
    source venv/bin/activate
    
    print_status "Upgrading pip..."
    pip install --upgrade pip
    
    print_status "Installing Python dependencies..."
    pip install -r requirements.txt
    
    print_status "Python environment setup complete"
}

# Setup Node.js dependencies for frontend
setup_frontend_deps() {
    print_header "Setting up Frontend Dependencies"
    
    if [ -d "dashboard/frontend" ]; then
        cd dashboard/frontend
        
        if [ -f "package.json" ]; then
            print_status "Installing frontend dependencies..."
            npm install
            print_status "Frontend dependencies installed"
        else
            print_warning "package.json not found in dashboard/frontend"
        fi
        
        cd ../..
    else
        print_warning "Frontend directory not found"
    fi
}

# Generate cryptographic keys for development
generate_dev_keys() {
    print_header "Generating Development Keys"
    
    # Create keys directory
    mkdir -p keys/dev
    
    if [ ! -f "keys/dev/private_key.pem" ]; then
        print_status "Generating RSA key pair..."
        
        # Activate virtual environment to use our dependencies
        source venv/bin/activate
        
        python3 -c "
from src.signing.key_manager import KeyManager
import os

key_manager = KeyManager()
private_path, public_path = key_manager.create_key_pair_files(
    key_type='RSA',
    private_key_path='keys/dev/private_key.pem',
    public_key_path='keys/dev/public_key.pem',
    key_size=2048
)
print(f'Generated keys: {private_path}, {public_path}')
"
        print_status "Development keys generated in keys/dev/"
    else
        print_status "Development keys already exist"
    fi
}

# Create configuration files
create_config_files() {
    print_header "Creating Configuration Files"
    
    # Create configuration directory
    mkdir -p config
    
    # Create main config file if it doesn't exist
    if [ ! -f "config/config.yaml" ]; then
        print_status "Creating default configuration..."
        cat > config/config.yaml << 'EOF'
# AI Artifact Supply Chain Trust Framework Configuration

# Signing configuration
signing:
  default_algorithm: "RSA-PSS"
  key_size: 2048
  key_storage_path: "./keys"

# Storage configuration
storage:
  backend: "local"  # Options: local, s3, azure, gcs
  local:
    sbom_path: "./data/sboms"
    registry_path: "./data/registry"
  
# Neo4j configuration
neo4j:
  uri: "bolt://localhost:7687"
  user: "neo4j"
  password: "ai-trust-password"

# API configuration
api:
  host: "0.0.0.0"
  port: 8000
  debug: true

# Verification settings
verification:
  strict_mode: true
  cache_results: true
  cache_ttl_seconds: 3600

# Logging configuration
logging:
  level: "INFO"
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  file: "./logs/ai-trust.log"
EOF
        print_status "Default configuration created"
    else
        print_status "Configuration file already exists"
    fi
}

# Initialize database schema
init_database() {
    print_header "Initializing Database Schema"
    
    # Check if Docker is available and Neo4j is running
    if command -v docker &> /dev/null; then
        if docker ps | grep -q ai-trust-neo4j; then
            print_status "Neo4j container is running"
            
            # TODO: Add database initialization script
            print_status "Database schema initialization would go here"
        else
            print_warning "Neo4j container is not running"
            print_status "Start services with: docker-compose up -d"
        fi
    else
        print_warning "Docker not available for database initialization"
    fi
}

# Create example artifacts for testing
create_examples() {
    print_header "Creating Example Artifacts"
    
    mkdir -p examples/artifacts
    
    # Create a simple Python script example
    if [ ! -f "examples/artifacts/example_model.py" ]; then
        cat > examples/artifacts/example_model.py << 'EOF'
#!/usr/bin/env python3
"""
Example ML model script for testing the AI Artifact Supply Chain Trust Framework
"""

import pickle
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.datasets import make_classification

def train_model():
    """Train a simple logistic regression model."""
    X, y = make_classification(n_samples=1000, n_features=20, random_state=42)
    
    model = LogisticRegression(random_state=42)
    model.fit(X, y)
    
    return model

def save_model(model, path):
    """Save model to pickle file."""
    with open(path, 'wb') as f:
        pickle.dump(model, f)

if __name__ == "__main__":
    model = train_model()
    save_model(model, "examples/artifacts/model.pkl")
    print("Model saved to examples/artifacts/model.pkl")
EOF
        print_status "Created example model script"
    fi
    
    # Create example config file
    if [ ! -f "examples/artifacts/config.json" ]; then
        cat > examples/artifacts/config.json << 'EOF'
{
  "model": {
    "name": "example_logistic_regression",
    "version": "1.0.0",
    "type": "classification",
    "framework": "scikit-learn"
  },
  "training": {
    "dataset": "synthetic_classification",
    "features": 20,
    "samples": 1000,
    "random_state": 42
  },
  "hyperparameters": {
    "solver": "lbfgs",
    "max_iter": 100,
    "random_state": 42
  },
  "dependencies": [
    "scikit-learn>=1.0.0",
    "numpy>=1.20.0"
  ]
}
EOF
        print_status "Created example configuration"
    fi
}

# Run basic tests to verify installation
run_tests() {
    print_header "Running Basic Tests"
    
    source venv/bin/activate
    
    # Test imports
    python3 -c "
try:
    from src.artifact_creation import SBOMGenerator
    from src.signing import ArtifactSigner, KeyManager
    print('✅ Core modules import successfully')
except ImportError as e:
    print(f'❌ Import error: {e}')
    exit(1)
"
    
    print_status "Basic tests passed"
}

# Main setup flow
main() {
    print_header "AI Artifact Supply Chain Trust Framework Setup"
    
    # Check prerequisites
    check_python
    check_nodejs
    
    # Setup environments
    setup_python_env
    setup_frontend_deps
    
    # Initialize project
    generate_dev_keys
    create_config_files
    create_examples
    
    # Create directories
    mkdir -p logs data/sboms data/registry
    
    # Run tests
    run_tests
    
    print_header "Setup Complete!"
    print_status "🎉 AI Artifact Supply Chain Trust Framework is ready!"
    echo ""
    print_status "Next steps:"
    echo "  1. Activate Python environment: source venv/bin/activate"
    echo "  2. Start services: docker-compose up -d"
    echo "  3. Run example: python examples/basic_usage.py"
    echo "  4. Open dashboard: http://localhost:3000"
    echo ""
    print_status "For more information, see README.md"
}

# Run main function
main "$@"
