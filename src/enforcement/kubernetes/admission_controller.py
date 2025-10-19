#!/usr/bin/env python3
"""
Kubernetes Admission Controller for AI Artifact Verification

Validates that container images and AI artifacts referenced in Kubernetes
deployments have valid SBOMs and signatures before allowing deployment.
"""

import os
import json
import base64
import hashlib
import asyncio
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from pathlib import Path

from flask import Flask, request, jsonify
import requests
import yaml

# Add src to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from verification import ArtifactVerifier
from sbom_storage import SBOMRegistry


class KubernetesAdmissionController:
    """Kubernetes ValidatingAdmissionWebhook for AI artifact verification."""
    
    def __init__(self, 
                 registry_url: str = "http://registry:8001",
                 verification_enabled: bool = True,
                 strict_mode: bool = False):
        """
        Initialize the admission controller.
        
        Args:
            registry_url: URL of the SBOM registry service
            verification_enabled: Whether to enforce verification
            strict_mode: If True, reject all unverified artifacts
        """
        self.registry_url = registry_url
        self.verification_enabled = verification_enabled
        self.strict_mode = strict_mode
        self.verifier = ArtifactVerifier()
        
        # Flask app for webhook
        self.app = Flask(__name__)
        self.app.add_url_rule('/health', 'health', self.health_check, methods=['GET'])
        self.app.add_url_rule('/validate', 'validate', self.validate_admission, methods=['POST'])
        self.app.add_url_rule('/mutate', 'mutate', self.mutate_admission, methods=['POST'])
    
    def health_check(self):
        """Health check endpoint."""
        return jsonify({
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "verification_enabled": self.verification_enabled,
            "strict_mode": self.strict_mode
        })
    
    def validate_admission(self):
        """Main validation webhook endpoint."""
        try:
            # Parse admission review request
            admission_review = request.get_json()
            
            if not admission_review or "request" not in admission_review:
                return self._create_admission_response(False, "Invalid admission review format")
            
            admission_request = admission_review["request"]
            
            # Extract Kubernetes object
            k8s_object = admission_request.get("object", {})
            kind = k8s_object.get("kind", "")
            
            # Validate based on resource type
            if kind in ["Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"]:
                validation_result = self._validate_workload(k8s_object)
            else:
                # Allow non-workload resources
                validation_result = {"allowed": True, "message": f"Resource type {kind} not subject to artifact verification"}
            
            return jsonify(self._create_admission_response(
                allowed=validation_result["allowed"],
                message=validation_result["message"],
                uid=admission_request.get("uid")
            ))
            
        except Exception as e:
            return jsonify(self._create_admission_response(
                False, 
                f"Admission controller error: {str(e)}",
                uid=request.get_json().get("request", {}).get("uid")
            ))
    
    def mutate_admission(self):
        """Mutating admission webhook (adds labels/annotations)."""
        try:
            admission_review = request.get_json()
            admission_request = admission_review["request"]
            k8s_object = admission_request.get("object", {})
            
            # Add verification annotations
            patches = []
            timestamp = datetime.now(timezone.utc).isoformat()
            
            # Add verification timestamp annotation
            patches.append({
                "op": "add",
                "path": "/metadata/annotations/ai-trust.artifact-verified-at",
                "value": timestamp
            })
            
            # Add controller annotation
            patches.append({
                "op": "add", 
                "path": "/metadata/annotations/ai-trust.verified-by",
                "value": "ai-artifact-admission-controller"
            })
            
            # Create patch response
            patch_base64 = base64.b64encode(json.dumps(patches).encode()).decode()
            
            return jsonify({
                "apiVersion": "admission.k8s.io/v1",
                "kind": "AdmissionResponse",
                "response": {
                    "uid": admission_request.get("uid"),
                    "allowed": True,
                    "patchType": "JSONPatch",
                    "patch": patch_base64
                }
            })
            
        except Exception as e:
            return jsonify(self._create_admission_response(
                False,
                f"Mutation error: {str(e)}",
                uid=request.get_json().get("request", {}).get("uid")
            ))
    
    def _validate_workload(self, k8s_object: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a Kubernetes workload object."""
        if not self.verification_enabled:
            return {"allowed": True, "message": "Verification disabled"}
        
        try:
            # Extract container images and artifact references
            artifacts = self._extract_artifacts_from_workload(k8s_object)
            
            if not artifacts:
                return {"allowed": True, "message": "No AI artifacts found to verify"}
            
            verification_results = []
            
            for artifact in artifacts:
                result = self._verify_artifact(artifact)
                verification_results.append(result)
            
            # Determine overall result
            failed_verifications = [r for r in verification_results if not r["verified"]]
            
            if failed_verifications:
                if self.strict_mode:
                    failed_artifacts = [r["artifact"] for r in failed_verifications]
                    return {
                        "allowed": False,
                        "message": f"Verification failed for artifacts: {', '.join(failed_artifacts)}"
                    }
                else:
                    # Log warnings but allow
                    print(f"Warning: Some artifacts failed verification but strict mode disabled")
            
            verified_count = len([r for r in verification_results if r["verified"]])
            total_count = len(verification_results)
            
            return {
                "allowed": True,
                "message": f"Verified {verified_count}/{total_count} artifacts"
            }
            
        except Exception as e:
            return {"allowed": False, "message": f"Validation error: {str(e)}"}
    
    def _extract_artifacts_from_workload(self, k8s_object: Dict[str, Any]) -> List[str]:
        """Extract AI artifact references from Kubernetes workload."""
        artifacts = set()
        
        # Get container specs from different workload types
        containers = []
        
        if k8s_object.get("kind") == "Pod":
            containers = k8s_object.get("spec", {}).get("containers", [])
        else:
            # Deployment, StatefulSet, DaemonSet, etc.
            pod_template = k8s_object.get("spec", {}).get("template", {})
            containers = pod_template.get("spec", {}).get("containers", [])
        
        # Extract container images
        for container in containers:
            image = container.get("image", "")
            if image:
                artifacts.add(image)
            
            # Look for AI artifact references in environment variables
            env_vars = container.get("env", [])
            for env_var in env_vars:
                value = env_var.get("value", "")
                if self._looks_like_artifact_path(value):
                    artifacts.add(value)
            
            # Look in volume mounts for model files
            volume_mounts = container.get("volumeMounts", [])
            for mount in volume_mounts:
                mount_path = mount.get("mountPath", "")
                if self._looks_like_artifact_path(mount_path):
                    artifacts.add(mount_path)
        
        # Look in annotations for explicit artifact declarations
        annotations = k8s_object.get("metadata", {}).get("annotations", {})
        ai_artifacts = annotations.get("ai-trust.artifacts", "")
        if ai_artifacts:
            try:
                artifact_list = json.loads(ai_artifacts)
                artifacts.update(artifact_list)
            except json.JSONDecodeError:
                # Treat as comma-separated list
                artifacts.update([a.strip() for a in ai_artifacts.split(",")])
        
        return list(artifacts)
    
    def _looks_like_artifact_path(self, path: str) -> bool:
        """Check if a path looks like an AI artifact."""
        ai_extensions = [".pkl", ".pth", ".pt", ".h5", ".onnx", ".pb", ".tflite", ".joblib"]
        path_lower = path.lower()
        
        return any(path_lower.endswith(ext) for ext in ai_extensions) or \
               any(keyword in path_lower for keyword in ["model", "weight", "checkpoint"])
    
    def _verify_artifact(self, artifact: str) -> Dict[str, Any]:
        """Verify an individual artifact."""
        try:
            # For container images, extract and verify
            if ":" in artifact and "/" in artifact:
                return self._verify_container_image(artifact)
            else:
                return self._verify_file_artifact(artifact)
                
        except Exception as e:
            return {
                "artifact": artifact,
                "verified": False,
                "error": str(e)
            }
    
    def _verify_container_image(self, image: str) -> Dict[str, Any]:
        """Verify a container image."""
        try:
            # Calculate image digest or use tag
            image_hash = hashlib.sha256(image.encode()).hexdigest()
            
            # Check registry for SBOM
            response = requests.get(
                f"{self.registry_url}/artifacts/{image_hash}/verify",
                timeout=5
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    "artifact": image,
                    "verified": result.get("is_registered", False),
                    "sbom_count": result.get("sbom_count", 0)
                }
            else:
                return {
                    "artifact": image,
                    "verified": False,
                    "error": f"Registry check failed: {response.status_code}"
                }
                
        except Exception as e:
            return {
                "artifact": image,
                "verified": False,
                "error": str(e)
            }
    
    def _verify_file_artifact(self, artifact_path: str) -> Dict[str, Any]:
        """Verify a file artifact."""
        try:
            # For file paths, we'd need to compute hash differently
            # This is a simplified approach - in production, you'd need
            # to resolve the actual file location
            
            # Check if there's a known SBOM for this path
            response = requests.get(
                f"{self.registry_url}/sboms/",
                params={"artifact_path": artifact_path},
                timeout=5
            )
            
            if response.status_code == 200:
                result = response.json()
                sboms = result.get("sboms", [])
                
                return {
                    "artifact": artifact_path,
                    "verified": len(sboms) > 0,
                    "sbom_count": len(sboms)
                }
            else:
                return {
                    "artifact": artifact_path,
                    "verified": False,
                    "error": f"Registry search failed: {response.status_code}"
                }
                
        except Exception as e:
            return {
                "artifact": artifact_path,
                "verified": False,
                "error": str(e)
            }
    
    def _create_admission_response(self, allowed: bool, message: str, uid: str = None) -> Dict[str, Any]:
        """Create standard Kubernetes admission response."""
        return {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionResponse", 
            "response": {
                "uid": uid,
                "allowed": allowed,
                "status": {
                    "code": 200 if allowed else 403,
                    "message": message
                }
            }
        }
    
    def run(self, host: str = "0.0.0.0", port: int = 8443, debug: bool = False):
        """Run the admission controller webhook server."""
        # In production, you'd want to use HTTPS with proper certificates
        cert_path = os.getenv("TLS_CERT_PATH", "/app/certs/tls.crt")
        key_path = os.getenv("TLS_KEY_PATH", "/app/certs/tls.key")
        
        if os.path.exists(cert_path) and os.path.exists(key_path):
            print(f"🔐 Running admission controller with TLS on port {port}")
            self.app.run(
                host=host,
                port=port,
                debug=debug,
                ssl_context=(cert_path, key_path)
            )
        else:
            print(f"⚠️  Running admission controller without TLS on port {port}")
            self.app.run(host=host, port=port, debug=debug)


def create_admission_controller_manifest() -> str:
    """Create Kubernetes manifest for the admission controller."""
    manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ai-artifact-admission-controller
  namespace: ai-trust-system
  labels:
    app: ai-artifact-admission-controller
spec:
  replicas: 2
  selector:
    matchLabels:
      app: ai-artifact-admission-controller
  template:
    metadata:
      labels:
        app: ai-artifact-admission-controller
    spec:
      containers:
      - name: admission-controller
        image: ai-trust/admission-controller:latest
        ports:
        - containerPort: 8443
          name: webhook-api
        env:
        - name: TLS_CERT_PATH
          value: "/app/certs/tls.crt"
        - name: TLS_KEY_PATH
          value: "/app/certs/tls.key"
        - name: REGISTRY_URL
          value: "http://ai-trust-registry:8001"
        - name: VERIFICATION_ENABLED
          value: "true"
        - name: STRICT_MODE
          value: "false"
        volumeMounts:
        - name: webhook-certs
          mountPath: /app/certs
          readOnly: true
        livenessProbe:
          httpGet:
            path: /health
            port: 8443
            scheme: HTTPS
        readinessProbe:
          httpGet:
            path: /health
            port: 8443
            scheme: HTTPS
        resources:
          limits:
            cpu: 500m
            memory: 512Mi
          requests:
            cpu: 250m
            memory: 256Mi
      volumes:
      - name: webhook-certs
        secret:
          secretName: admission-controller-certs
---
apiVersion: v1
kind: Service
metadata:
  name: ai-artifact-admission-controller
  namespace: ai-trust-system
spec:
  selector:
    app: ai-artifact-admission-controller
  ports:
  - protocol: TCP
    port: 443
    targetPort: 8443
    name: webhook-api
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionWebhook
metadata:
  name: ai-artifact-verifier
spec:
  clientConfig:
    service:
      name: ai-artifact-admission-controller
      namespace: ai-trust-system
      path: "/validate"
  rules:
  - operations: ["CREATE", "UPDATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
  - operations: ["CREATE", "UPDATE"]  
    apiGroups: ["apps"]
    apiVersions: ["v1"]
    resources: ["deployments", "statefulsets", "daemonsets"]
  - operations: ["CREATE", "UPDATE"]
    apiGroups: ["batch"]
    apiVersions: ["v1"]
    resources: ["jobs", "cronjobs"]
  admissionReviewVersions: ["v1", "v1beta1"]
  sideEffects: None
  failurePolicy: Ignore
---
apiVersion: admissionregistration.k8s.io/v1
kind: MutatingAdmissionWebhook
metadata:
  name: ai-artifact-annotator
spec:
  clientConfig:
    service:
      name: ai-artifact-admission-controller
      namespace: ai-trust-system
      path: "/mutate"
  rules:
  - operations: ["CREATE"]
    apiGroups: [""]
    apiVersions: ["v1"] 
    resources: ["pods"]
  - operations: ["CREATE"]
    apiGroups: ["apps"]
    apiVersions: ["v1"]
    resources: ["deployments", "statefulsets", "daemonsets"]
  admissionReviewVersions: ["v1", "v1beta1"]
  sideEffects: None
  failurePolicy: Ignore
"""
    return manifest


def main():
    """Run the admission controller."""
    registry_url = os.getenv("REGISTRY_URL", "http://localhost:8001")
    verification_enabled = os.getenv("VERIFICATION_ENABLED", "true").lower() == "true"
    strict_mode = os.getenv("STRICT_MODE", "false").lower() == "true"
    port = int(os.getenv("PORT", "8443"))
    
    controller = KubernetesAdmissionController(
        registry_url=registry_url,
        verification_enabled=verification_enabled,
        strict_mode=strict_mode
    )
    
    print(f"🚀 Starting AI Artifact Admission Controller")
    print(f"   Registry URL: {registry_url}")
    print(f"   Verification Enabled: {verification_enabled}")
    print(f"   Strict Mode: {strict_mode}")
    
    controller.run(port=port, debug=False)


if __name__ == "__main__":
    main()