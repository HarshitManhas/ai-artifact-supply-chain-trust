"""
Kubernetes Enforcement Module

Provides admission controller capabilities for Kubernetes to ensure
only verified AI artifacts are deployed in the cluster.
"""

from .admission_controller import AdmissionController

__all__ = ['AdmissionController']