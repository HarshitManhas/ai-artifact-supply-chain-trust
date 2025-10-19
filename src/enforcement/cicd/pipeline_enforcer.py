"""
Pipeline Enforcer Module

Provides enforcement capabilities for various CI/CD pipelines to ensure
only verified AI artifacts are used in builds and deployments.
"""

import os
import json
from typing import Dict, List, Any, Optional
from pathlib import Path

import sys
sys.path.append(str(Path(__file__).parent.parent.parent))

from verification.artifact_verifier import ArtifactVerifier


class PipelineEnforcementResult:
    """Result of pipeline enforcement check."""
    
    def __init__(self, is_allowed: bool, violations: List[Dict[str, Any]], summary: str):
        self.is_allowed = is_allowed
        self.violations = violations
        self.summary = summary
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'is_allowed': self.is_allowed,
            'violations': self.violations,
            'summary': self.summary
        }


class PipelineEnforcer:
    """Enforces artifact verification in CI/CD pipelines."""
    
    def __init__(self, 
                 sbom_registry_url: Optional[str] = None,
                 enforcement_mode: str = 'strict',
                 allowed_extensions: Optional[List[str]] = None):
        """
        Initialize pipeline enforcer.
        
        Args:
            sbom_registry_url: URL of SBOM registry service
            enforcement_mode: 'strict' (fail on violations) or 'warn' (log warnings only)
            allowed_extensions: List of file extensions to check
        """
        self.verifier = ArtifactVerifier()
        self.sbom_registry_url = sbom_registry_url
        self.enforcement_mode = enforcement_mode
        self.allowed_extensions = allowed_extensions or [
            '.pkl', '.pickle', '.pth', '.pt', '.h5', '.hdf5', 
            '.onnx', '.pb', '.joblib', '.csv', '.parquet'
        ]
    
    def check_artifacts_in_directory(self, 
                                   directory_path: str,
                                   sbom_directory: Optional[str] = None) -> PipelineEnforcementResult:
        """
        Check all artifacts in a directory against their SBOMs.
        
        Args:
            directory_path: Directory containing artifacts to check
            sbom_directory: Directory containing corresponding SBOM files
            
        Returns:
            PipelineEnforcementResult
        """
        violations = []
        
        # Find all artifact files
        artifact_files = []
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                if any(file.endswith(ext) for ext in self.allowed_extensions):
                    artifact_files.append(file_path)
        
        if not artifact_files:
            return PipelineEnforcementResult(
                is_allowed=True,
                violations=[],
                summary="No artifacts found to verify"
            )
        
        # Check each artifact
        for artifact_path in artifact_files:
            violation = self._check_single_artifact(artifact_path, sbom_directory)
            if violation:
                violations.append(violation)
        
        # Determine result
        is_allowed = len(violations) == 0 or self.enforcement_mode == 'warn'
        
        summary = f"Checked {len(artifact_files)} artifacts, found {len(violations)} violations"
        
        return PipelineEnforcementResult(
            is_allowed=is_allowed,
            violations=violations,
            summary=summary
        )
    
    def _check_single_artifact(self, 
                             artifact_path: str, 
                             sbom_directory: Optional[str]) -> Optional[Dict[str, Any]]:
        """Check a single artifact against its SBOM."""
        artifact_name = os.path.basename(artifact_path)
        
        # Look for corresponding SBOM file
        sbom_path = None
        if sbom_directory:
            # Try various naming conventions
            possible_names = [
                f"{artifact_name}.sbom.json",
                f"{os.path.splitext(artifact_name)[0]}.sbom.json",
                f"sbom_{artifact_name}.json",
                f"sbom_{os.path.splitext(artifact_name)[0]}.json"
            ]
            
            for name in possible_names:
                candidate_path = os.path.join(sbom_directory, name)
                if os.path.exists(candidate_path):
                    sbom_path = candidate_path
                    break
        
        if not sbom_path:
            return {
                'type': 'missing_sbom',
                'artifact_path': artifact_path,
                'message': f'No SBOM file found for artifact: {artifact_name}',
                'severity': 'high'
            }
        
        # Verify artifact against SBOM
        try:
            verification_result = self.verifier.verify_artifact_from_file(
                artifact_path, sbom_path, is_signed=True
            )
            
            if not verification_result.is_valid:
                return {
                    'type': 'verification_failed',
                    'artifact_path': artifact_path,
                    'sbom_path': sbom_path,
                    'message': f'Artifact verification failed: {"; ".join(verification_result.messages)}',
                    'severity': 'high'
                }
        
        except Exception as e:
            return {
                'type': 'verification_error',
                'artifact_path': artifact_path,
                'sbom_path': sbom_path,
                'message': f'Error during verification: {str(e)}',
                'severity': 'medium'
            }
        
        return None
    
    def generate_github_actions_workflow(self, 
                                      artifacts_path: str = "artifacts/",
                                      sboms_path: str = "sboms/") -> str:
        """
        Generate GitHub Actions workflow YAML for artifact verification.
        
        Args:
            artifacts_path: Path to artifacts in repository
            sboms_path: Path to SBOMs in repository
            
        Returns:
            YAML workflow content
        """
        workflow = f"""
name: AI Artifact Verification

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  verify-artifacts:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
    
    - name: Verify AI Artifacts
      run: |
        python -c "
import sys
sys.path.append('src')
from enforcement.cicd.pipeline_enforcer import PipelineEnforcer

enforcer = PipelineEnforcer(enforcement_mode='strict')
result = enforcer.check_artifacts_in_directory('{artifacts_path}', '{sboms_path}')

print(f'Verification Summary: {{result.summary}}')

if result.violations:
    print('Violations found:')
    for violation in result.violations:
        print(f'  - {{violation[\\"message\\"]}}')

if not result.is_allowed:
    print('❌ Artifact verification failed!')
    sys.exit(1)
else:
    print('✅ All artifacts verified successfully!')
        "
"""
        return workflow
    
    def generate_jenkins_pipeline(self, 
                                artifacts_path: str = "artifacts/",
                                sboms_path: str = "sboms/") -> str:
        """
        Generate Jenkins pipeline script for artifact verification.
        
        Args:
            artifacts_path: Path to artifacts
            sboms_path: Path to SBOMs
            
        Returns:
            Jenkinsfile content
        """
        pipeline = f"""
pipeline {{
    agent any
    
    stages {{
        stage('Checkout') {{
            steps {{
                checkout scm
            }}
        }}
        
        stage('Install Dependencies') {{
            steps {{
                sh 'pip install -r requirements.txt'
            }}
        }}
        
        stage('Verify AI Artifacts') {{
            steps {{
                script {{
                    def verificationScript = '''
import sys
sys.path.append('src')
from enforcement.cicd.pipeline_enforcer import PipelineEnforcer

enforcer = PipelineEnforcer(enforcement_mode='strict')
result = enforcer.check_artifacts_in_directory('{artifacts_path}', '{sboms_path}')

print(f'Verification Summary: {{result.summary}}')

if result.violations:
    print('Violations found:')
    for violation in result.violations:
        print(f'  - {{violation["message"]}}')

if not result.is_allowed:
    print('❌ Artifact verification failed!')
    exit(1)
else:
    print('✅ All artifacts verified successfully!')
                    '''
                    
                    sh "python -c \\"$verificationScript\\""
                }}
            }}
        }}
    }}
    
    post {{
        always {{
            echo 'AI Artifact verification completed'
        }}
        success {{
            echo '✅ All artifacts verified successfully'
        }}
        failure {{
            echo '❌ Artifact verification failed'
        }}
    }}
}}
"""
        return pipeline
    
    def generate_gitlab_ci_config(self, 
                                artifacts_path: str = "artifacts/",
                                sboms_path: str = "sboms/") -> str:
        """
        Generate GitLab CI configuration for artifact verification.
        
        Args:
            artifacts_path: Path to artifacts
            sboms_path: Path to SBOMs
            
        Returns:
            .gitlab-ci.yml content
        """
        config = f"""
stages:
  - verify-artifacts

variables:
  ARTIFACTS_PATH: "{artifacts_path}"
  SBOMS_PATH: "{sboms_path}"

verify_ai_artifacts:
  stage: verify-artifacts
  image: python:3.9
  
  before_script:
    - pip install -r requirements.txt
  
  script:
    - |
      python -c "
      import sys
      sys.path.append('src')
      from enforcement.cicd.pipeline_enforcer import PipelineEnforcer

      enforcer = PipelineEnforcer(enforcement_mode='strict')
      result = enforcer.check_artifacts_in_directory('$ARTIFACTS_PATH', '$SBOMS_PATH')

      print(f'Verification Summary: {{result.summary}}')

      if result.violations:
          print('Violations found:')
          for violation in result.violations:
              print(f'  - {{violation[\"message\"]}}')

      if not result.is_allowed:
          print('❌ Artifact verification failed!')
          exit(1)
      else:
          print('✅ All artifacts verified successfully!')
      "
  
  rules:
    - if: '$CI_COMMIT_BRANCH == "main" || $CI_COMMIT_BRANCH == "develop"'
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
"""
        return config
    
    def save_pipeline_configs(self, output_directory: str):
        """
        Save all pipeline configuration files.
        
        Args:
            output_directory: Directory to save configuration files
        """
        output_path = Path(output_directory)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # GitHub Actions
        github_workflow = self.generate_github_actions_workflow()
        github_dir = output_path / ".github" / "workflows"
        github_dir.mkdir(parents=True, exist_ok=True)
        with open(github_dir / "ai-artifact-verification.yml", 'w') as f:
            f.write(github_workflow)
        
        # Jenkins
        jenkins_pipeline = self.generate_jenkins_pipeline()
        with open(output_path / "Jenkinsfile", 'w') as f:
            f.write(jenkins_pipeline)
        
        # GitLab CI
        gitlab_config = self.generate_gitlab_ci_config()
        with open(output_path / ".gitlab-ci.yml", 'w') as f:
            f.write(gitlab_config)
        
        print(f"✅ Pipeline configuration files saved to: {output_directory}")
        print("   • GitHub Actions: .github/workflows/ai-artifact-verification.yml")
        print("   • Jenkins: Jenkinsfile")
        print("   • GitLab CI: .gitlab-ci.yml")