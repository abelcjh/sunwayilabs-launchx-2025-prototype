"""
Zero-Knowledge Machine Learning module for privacy-preserving compliance verification.

This module provides zero-knowledge proof capabilities for demonstrating
policy compliance without exposing raw conversation text.
"""

from .zkml_proof import (
    ZKMLProver,
    ZKMLVerifier, 
    ZKMLComplianceManager,
    ZKMLProof,
    ComplianceCircuit,
    ProofType,
    create_zkml_smart_contract_interface
)

__all__ = [
    'ZKMLProver',
    'ZKMLVerifier',
    'ZKMLComplianceManager', 
    'ZKMLProof',
    'ComplianceCircuit',
    'ProofType',
    'create_zkml_smart_contract_interface'
]
