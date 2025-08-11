#!/usr/bin/env python3
"""
SyftBox Privacy Integration

Integrates the privacy instruction system with SyftBox's native permission system
to ensure tamper-proof storage and access control for privacy rules.

This module bridges between SyftBox permissions and our privacy instruction parser.
"""

import asyncio
import logging
from pathlib import Path
from typing import Optional, Dict, List, Tuple
import hashlib
import json
from datetime import datetime

# SyftBox integration
try:
    from syftbox.lib.permissions import get_computed_permission, PermissionType
    SYFTBOX_AVAILABLE = True
except ImportError:
    SYFTBOX_AVAILABLE = False
    logging.warning("SyftBox library not available - running in fallback mode")

from privacy_instructions import PrivacyInstructionParser, PrivacyInstructions

logger = logging.getLogger(__name__)

class SyftBoxPrivacyManager:
    """
    Manages privacy instructions with SyftBox permission system integration.
    
    Ensures that:
    1. Privacy instructions are stored in protected SyftBox locations
    2. Only data owners can modify privacy rules
    3. Instruction integrity is cryptographically verified
    4. Access is logged and audited through SyftBox
    """
    
    def __init__(self, datasite_path: Path, user_email: str):
        """Initialize SyftBox privacy manager."""
        self.datasite_path = Path(datasite_path)
        self.user_email = user_email
        
        # Privacy instructions are stored in protected private folder
        self.privacy_instructions_path = self.datasite_path / "private" / ".privacy_instructions"
        self.audit_log_path = self.datasite_path / "private" / ".privacy_audit"
        
        # Create directories if needed
        self.privacy_instructions_path.mkdir(parents=True, exist_ok=True)
        self.audit_log_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize instruction parser
        self.instruction_parser = PrivacyInstructionParser(self.privacy_instructions_path)
        
        # Track loaded instructions
        self.loaded_instructions: Dict[str, PrivacyInstructions] = {}
        self.last_integrity_check = datetime.now()
        
    async def initialize(self) -> bool:
        """Initialize the privacy manager and load all instructions."""
        try:
            logger.info(f"Initializing SyftBox privacy manager for {self.user_email}")
            
            # Verify SyftBox integration
            if not SYFTBOX_AVAILABLE:
                logger.warning("SyftBox library not available - using fallback mode")
                return await self._initialize_fallback_mode()
            
            # Check permissions on privacy instructions directory
            if not await self._verify_privacy_directory_permissions():
                logger.error("Failed to verify privacy directory permissions")
                return False
            
            # Load all privacy instructions
            await self._load_all_privacy_instructions()
            
            # Verify instruction integrity
            if not await self._verify_all_instruction_integrity():
                logger.error("Instruction integrity verification failed")
                return False
            
            logger.info(f"Privacy manager initialized with {len(self.loaded_instructions)} instruction sets")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize SyftBox privacy manager: {e}")
            return False
    
    async def _initialize_fallback_mode(self) -> bool:
        """Initialize without SyftBox integration (for testing/development)."""
        logger.info("Initializing in fallback mode (no SyftBox permission checking)")
        
        try:
            await self._load_all_privacy_instructions()
            logger.info(f"Fallback mode initialized with {len(self.loaded_instructions)} instruction sets")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize fallback mode: {e}")
            return False
    
    async def _verify_privacy_directory_permissions(self) -> bool:
        """Verify that privacy instructions directory has proper SyftBox permissions."""
        if not SYFTBOX_AVAILABLE:
            return True  # Skip verification in fallback mode
            
        try:
            # Get the datasite snapshot folder (parent of datasites)
            snapshot_folder = self.datasite_path.parent.parent
            
            # Calculate relative path for permission checking
            relative_path = self.privacy_instructions_path.relative_to(snapshot_folder)
            
            # Check SyftBox permissions
            computed_perm = get_computed_permission(
                snapshot_folder=snapshot_folder,
                user_email=self.user_email,
                path=relative_path
            )
            
            # Data owner should have admin permissions on privacy instructions
            if computed_perm.permission in [PermissionType.ADMIN, PermissionType.WRITE]:
                logger.info(f"Privacy directory permissions verified: {computed_perm.permission}")
                return True
            else:
                logger.error(f"Insufficient permissions on privacy directory: {computed_perm.permission}")
                return False
                
        except Exception as e:
            logger.error(f"Error verifying privacy directory permissions: {e}")
            return False
    
    async def _load_all_privacy_instructions(self):
        """Load all privacy instruction files."""
        try:
            self.loaded_instructions = await self.instruction_parser.load_all_instructions()
            logger.info(f"Loaded {len(self.loaded_instructions)} privacy instruction files")
        except Exception as e:
            logger.error(f"Failed to load privacy instructions: {e}")
            raise
    
    async def _verify_all_instruction_integrity(self) -> bool:
        """Verify integrity of all loaded instructions."""
        try:
            all_valid = True
            
            # Check document-specific instructions
            for doc_name, instructions in self.loaded_instructions.items():
                is_valid = self.instruction_parser.validate_instruction_integrity(instructions)
                if not is_valid:
                    logger.error(f"Integrity check failed for: {doc_name}")
                    all_valid = False
                    await self._log_security_violation(
                        "integrity_check_failed",
                        f"Instruction integrity check failed for {doc_name}",
                        {"document": doc_name, "file_path": str(instructions.loaded_from)}
                    )
                else:
                    logger.debug(f"Integrity verified for: {doc_name}")
            
            # Check global defaults
            if self.instruction_parser.global_defaults:
                is_valid = self.instruction_parser.validate_instruction_integrity(
                    self.instruction_parser.global_defaults
                )
                if not is_valid:
                    logger.error("Integrity check failed for global defaults")
                    all_valid = False
                    await self._log_security_violation(
                        "integrity_check_failed",
                        "Global defaults integrity check failed",
                        {"file_path": str(self.instruction_parser.global_defaults.loaded_from)}
                    )
            
            return all_valid
            
        except Exception as e:
            logger.error(f"Error during integrity verification: {e}")
            return False
    
    async def get_privacy_instructions(self, document_name: str) -> Optional[PrivacyInstructions]:
        """
        Get privacy instructions for a document with SyftBox permission checking.
        
        Args:
            document_name: Name of the document to get instructions for
            
        Returns:
            PrivacyInstructions object or None if not found/not permitted
        """
        try:
            # Periodic integrity check (every hour)
            if (datetime.now() - self.last_integrity_check).total_seconds() > 3600:
                logger.info("Performing periodic integrity check")
                if not await self._verify_all_instruction_integrity():
                    logger.error("Periodic integrity check failed - potential tampering detected")
                    return None
                self.last_integrity_check = datetime.now()
            
            # Get instructions using parser
            instructions = self.instruction_parser.get_instructions_for_document(document_name)
            
            if not instructions:
                logger.warning(f"No privacy instructions found for: {document_name}")
                return None
            
            # Log access for audit
            await self._log_privacy_access(
                "instruction_access",
                f"Retrieved privacy instructions for {document_name}",
                {
                    "document": document_name,
                    "instruction_file": str(instructions.loaded_from),
                    "protection_level": str(instructions.fallback_config.default_protection_level)
                }
            )
            
            return instructions
            
        except Exception as e:
            logger.error(f"Error retrieving privacy instructions for {document_name}: {e}")
            await self._log_security_violation(
                "instruction_access_error", 
                f"Error accessing instructions for {document_name}",
                {"document": document_name, "error": str(e)}
            )
            return None
    
    async def validate_instruction_modification(
        self, 
        document_name: str, 
        requester_email: str
    ) -> Tuple[bool, str]:
        """
        Validate if a user can modify privacy instructions for a document.
        
        Args:
            document_name: Document whose instructions are being modified
            requester_email: Email of user requesting modification
            
        Returns:
            Tuple of (allowed, reason)
        """
        try:
            # Only data owner can modify privacy instructions
            if requester_email != self.user_email:
                reason = f"Only data owner ({self.user_email}) can modify privacy instructions"
                logger.warning(f"Unauthorized modification attempt by {requester_email}: {reason}")
                await self._log_security_violation(
                    "unauthorized_modification_attempt",
                    reason,
                    {
                        "document": document_name,
                        "requester": requester_email,
                        "owner": self.user_email
                    }
                )
                return False, reason
            
            # Verify SyftBox permissions if available
            if SYFTBOX_AVAILABLE:
                instruction_file_path = self.privacy_instructions_path / f"{document_name}.yaml"
                if not await self._check_write_permission(requester_email, instruction_file_path):
                    reason = f"SyftBox permissions deny write access to {instruction_file_path}"
                    logger.error(reason)
                    return False, reason
            
            return True, "Modification allowed"
            
        except Exception as e:
            reason = f"Error validating modification permission: {e}"
            logger.error(reason)
            return False, reason
    
    async def _check_write_permission(self, user_email: str, file_path: Path) -> bool:
        """Check if user has write permission to a file through SyftBox."""
        if not SYFTBOX_AVAILABLE:
            return True  # Skip check in fallback mode
            
        try:
            snapshot_folder = self.datasite_path.parent.parent
            relative_path = file_path.relative_to(snapshot_folder)
            
            computed_perm = get_computed_permission(
                snapshot_folder=snapshot_folder,
                user_email=user_email,
                path=relative_path
            )
            
            return computed_perm.permission in [PermissionType.ADMIN, PermissionType.WRITE]
            
        except Exception as e:
            logger.error(f"Error checking write permission: {e}")
            return False
    
    async def _log_privacy_access(self, event_type: str, message: str, details: Dict):
        """Log privacy-related access for audit purposes."""
        try:
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "event_type": event_type,
                "user_email": self.user_email,
                "message": message,
                "details": details
            }
            
            # Write to audit log
            audit_file = self.audit_log_path / f"privacy_access_{datetime.now().strftime('%Y%m%d')}.jsonl"
            with open(audit_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry) + '\n')
            
        except Exception as e:
            logger.error(f"Failed to write privacy audit log: {e}")
    
    async def _log_security_violation(self, violation_type: str, message: str, details: Dict):
        """Log security violations for immediate attention."""
        try:
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "violation_type": violation_type,
                "user_email": self.user_email,
                "message": message,
                "details": details,
                "severity": "HIGH"
            }
            
            # Write to security violations log
            security_file = self.audit_log_path / f"security_violations_{datetime.now().strftime('%Y%m%d')}.jsonl"
            with open(security_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry) + '\n')
            
            # Also log at ERROR level for immediate visibility
            logger.error(f"SECURITY VIOLATION [{violation_type}]: {message}")
            
        except Exception as e:
            logger.error(f"CRITICAL: Failed to log security violation: {e}")
    
    def get_privacy_statistics(self) -> Dict[str, any]:
        """Get statistics about loaded privacy instructions."""
        try:
            stats = {
                "total_instructions": len(self.loaded_instructions),
                "has_global_defaults": self.instruction_parser.global_defaults is not None,
                "instruction_files": [],
                "last_integrity_check": self.last_integrity_check.isoformat(),
                "privacy_directory": str(self.privacy_instructions_path),
                "syftbox_integration": SYFTBOX_AVAILABLE
            }
            
            for doc_name, instructions in self.loaded_instructions.items():
                file_stats = {
                    "document": doc_name,
                    "sensitivity": str(instructions.document_config.content_sensitivity),
                    "protection_level": str(instructions.fallback_config.default_protection_level),
                    "entropy_budget": instructions.privacy_budget.total_entropy_budget,
                    "protected_facts": len(instructions.protected_facts),
                    "protected_themes": len(instructions.protected_themes),
                    "file_path": str(instructions.loaded_from),
                    "is_valid": instructions.is_valid
                }
                stats["instruction_files"].append(file_stats)
            
            return stats
            
        except Exception as e:
            logger.error(f"Error generating privacy statistics: {e}")
            return {"error": str(e)}

# Global instance for use by other components
_privacy_manager_instance: Optional[SyftBoxPrivacyManager] = None

async def get_privacy_manager(datasite_path: Path, user_email: str) -> Optional[SyftBoxPrivacyManager]:
    """Get or create the global privacy manager instance."""
    global _privacy_manager_instance
    
    if _privacy_manager_instance is None:
        _privacy_manager_instance = SyftBoxPrivacyManager(datasite_path, user_email)
        success = await _privacy_manager_instance.initialize()
        if not success:
            logger.error("Failed to initialize privacy manager")
            _privacy_manager_instance = None
    
    return _privacy_manager_instance