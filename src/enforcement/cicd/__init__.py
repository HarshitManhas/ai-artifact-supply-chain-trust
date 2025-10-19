"""
CI/CD Enforcement Module

Provides enforcement capabilities for CI/CD pipelines including
GitHub Actions, Jenkins, GitLab CI, and Azure DevOps.
"""

from .pipeline_enforcer import PipelineEnforcer

__all__ = ['PipelineEnforcer']