#!/usr/bin/env python3
"""
Privacy Instructions Parser and Validator

This module handles loading, validating, and parsing privacy instruction YAML files
for the LLM-based privacy filter system. It implements the schema defined in 
Phase 1.1 and provides structured access to privacy rules.

Based on information-theoretic privacy research and semantic content protection.
"""

import asyncio
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, Tuple
import yaml
from enum import Enum

logger = logging.getLogger(__name__)

class ProtectionLevel(Enum):
    """Privacy protection levels for different content categories."""
    LOW = "low"
    MEDIUM = "medium" 
    HIGH = "high"
    ABSOLUTE = "absolute"

class ResponseStrategy(Enum):
    """Strategies for responding to different query types."""
    ALLOW = "allow"
    PARTIAL = "partial"
    ABSTRACT = "abstract"
    DEFLECT = "deflect"
    REFUSE = "refuse"

class ContentSensitivity(Enum):
    """Overall sensitivity levels for documents."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ProtectedFact:
    """Individual protected fact or concept."""
    category: str  # entities, concepts, relationships, temporal, quantitative
    items: List[str]
    protection_level: ProtectionLevel
    
    def __post_init__(self):
        if isinstance(self.protection_level, str):
            self.protection_level = ProtectionLevel(self.protection_level)

@dataclass
class ProtectedTheme:
    """Semantic theme that should be protected."""
    theme: str
    description: str
    abstraction_level: str  # absolute, high, medium, low
    
@dataclass
class ShareableContent:
    """Content that can be shared with limitations."""
    open_topics: List[str] = field(default_factory=list)
    conditional_sharing: List[Dict[str, Any]] = field(default_factory=list)

@dataclass 
class ResponseBehavior:
    """How to respond to different types of queries."""
    direct_fact_queries: Dict[str, Any] = field(default_factory=dict)
    analytical_queries: Dict[str, Any] = field(default_factory=dict)
    creative_queries: Dict[str, Any] = field(default_factory=dict)
    extraction_attempts: Dict[str, Any] = field(default_factory=dict)

@dataclass
class PrivacyBudget:
    """Information-theoretic privacy budget configuration."""
    total_entropy_budget: float
    per_session_entropy_limit: float
    daily_entropy_reset: bool
    
    # Query limits
    max_queries_per_hour: int
    max_queries_per_day: int
    cooldown_period_minutes: int
    
    # Semantic constraints
    similarity_threshold: float
    cumulative_similarity_limit: float
    similarity_decay_hours: int

@dataclass
class MultiAgentProtection:
    """Configuration for multi-agent coordination protection."""
    global_budget_sharing: bool
    collective_entropy_limit: float
    detect_coordinated_queries: bool
    coordination_similarity_threshold: float
    coordination_time_window_hours: int
    diversify_responses: bool
    diversification_strategy: str

@dataclass
class SecurityConfig:
    """Security and tampering protection configuration."""
    require_signature: bool
    signature_algorithm: str
    owner_public_key: str
    integrity_checks: bool
    checksum_algorithm: str
    audit_logging: bool
    log_all_queries: bool
    log_all_responses: bool
    log_privacy_violations: bool = True

@dataclass
class FallbackConfig:
    """Fallback behaviors for edge cases and errors."""
    default_protection_level: ProtectionLevel
    uncertainty_strategy: str
    parsing_error_response: str
    budget_exceeded_response: str
    protection_violation_response: str
    partial_failure_mode: str
    complete_failure_mode: str
    
    def __post_init__(self):
        if isinstance(self.default_protection_level, str):
            self.default_protection_level = ProtectionLevel(self.default_protection_level)

@dataclass
class DocumentConfig:
    """Configuration for the target document."""
    target_document: str
    document_type: str  # text, code, data, mixed
    content_sensitivity: ContentSensitivity
    
    def __post_init__(self):
        if isinstance(self.content_sensitivity, str):
            self.content_sensitivity = ContentSensitivity(self.content_sensitivity)

@dataclass
class PrivacyInstructions:
    """Complete privacy instructions for a document."""
    schema_version: str
    document_config: DocumentConfig
    core_protected_content: Dict[str, Any]
    shareable_content: ShareableContent
    response_behavior: ResponseBehavior
    privacy_budget: PrivacyBudget
    multi_agent_protection: MultiAgentProtection
    security_config: SecurityConfig
    fallback_config: FallbackConfig
    metadata: Dict[str, Any]
    
    # Parsed protected facts and themes
    protected_facts: List[ProtectedFact] = field(default_factory=list)
    protected_themes: List[ProtectedTheme] = field(default_factory=list)
    
    # Validation state
    is_valid: bool = False
    validation_errors: List[str] = field(default_factory=list)
    file_hash: Optional[str] = None
    loaded_from: Optional[Path] = None

class PrivacyInstructionParser:
    """Parser and validator for privacy instruction YAML files."""
    
    SUPPORTED_SCHEMA_VERSIONS = ["1.0"]
    REQUIRED_SECTIONS = [
        "schema_version", "document_config", "core_protected_content",
        "shareable_content", "response_behavior", "privacy_budget", 
        "security_config", "fallback_config", "metadata"
    ]
    
    def __init__(self, instructions_path: Path):
        """Initialize parser with path to privacy instructions directory."""
        self.instructions_path = Path(instructions_path)
        self.loaded_instructions: Dict[str, PrivacyInstructions] = {}
        self.global_defaults: Optional[PrivacyInstructions] = None
        
    async def load_all_instructions(self) -> Dict[str, PrivacyInstructions]:
        """Load all privacy instruction files from the directory."""
        if not self.instructions_path.exists():
            logger.error(f"Privacy instructions directory not found: {self.instructions_path}")
            return {}
            
        instruction_files = list(self.instructions_path.glob("*.yaml"))
        logger.info(f"Found {len(instruction_files)} privacy instruction files")
        
        for file_path in instruction_files:
            try:
                instructions = await self.load_instructions(file_path)
                if instructions and instructions.is_valid:
                    if file_path.name == "global_defaults.yaml":
                        self.global_defaults = instructions
                        logger.info("Loaded global default privacy instructions")
                    else:
                        doc_name = instructions.document_config.target_document
                        self.loaded_instructions[doc_name] = instructions
                        logger.info(f"Loaded privacy instructions for: {doc_name}")
                else:
                    logger.error(f"Failed to load valid instructions from: {file_path}")
            except Exception as e:
                logger.error(f"Error loading privacy instructions from {file_path}: {e}")
        
        return self.loaded_instructions
    
    async def load_instructions(self, file_path: Path) -> Optional[PrivacyInstructions]:
        """Load and validate privacy instructions from a YAML file."""
        try:
            logger.info(f"Loading privacy instructions from: {file_path}")
            
            # Read and parse YAML
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                data = yaml.safe_load(content)
            
            # Calculate file hash for integrity
            file_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
            
            # Validate structure
            validation_errors = self._validate_structure(data, file_path)
            if validation_errors:
                logger.error(f"Validation errors in {file_path}: {validation_errors}")
                return None
                
            # Parse into structured format
            instructions = self._parse_instructions(data, file_path, file_hash)
            
            if instructions:
                logger.info(f"Successfully loaded privacy instructions for: {instructions.document_config.target_document}")
                return instructions
            else:
                logger.error(f"Failed to parse instructions from: {file_path}")
                return None
                
        except Exception as e:
            logger.error(f"Error loading privacy instructions from {file_path}: {e}")
            return None
    
    def _validate_structure(self, data: Dict[str, Any], file_path: Path) -> List[str]:
        """Validate the structure of privacy instruction data."""
        errors = []
        
        # Check schema version
        schema_version = data.get("schema_version")
        if not schema_version:
            errors.append("Missing required field: schema_version")
        elif schema_version not in self.SUPPORTED_SCHEMA_VERSIONS:
            errors.append(f"Unsupported schema version: {schema_version}")
        
        # Check required sections
        for section in self.REQUIRED_SECTIONS:
            if section not in data:
                errors.append(f"Missing required section: {section}")
        
        # Validate document config
        if "document_config" in data:
            doc_config = data["document_config"]
            required_doc_fields = ["target_document", "document_type", "content_sensitivity"]
            for field in required_doc_fields:
                if field not in doc_config:
                    errors.append(f"Missing document_config field: {field}")
        
        # Validate privacy budget
        if "privacy_budget" in data:
            budget = data["privacy_budget"]
            required_budget_fields = ["total_entropy_budget", "per_session_entropy_limit"]
            for field in required_budget_fields:
                if field not in budget:
                    errors.append(f"Missing privacy_budget field: {field}")
                elif not isinstance(budget[field], (int, float)):
                    errors.append(f"Invalid privacy_budget field {field}: must be numeric")
        
        return errors
    
    def _parse_instructions(self, data: Dict[str, Any], file_path: Path, file_hash: str) -> Optional[PrivacyInstructions]:
        """Parse validated YAML data into PrivacyInstructions object."""
        try:
            # Parse document config
            doc_config_data = data["document_config"]
            document_config = DocumentConfig(
                target_document=doc_config_data["target_document"],
                document_type=doc_config_data["document_type"],
                content_sensitivity=doc_config_data["content_sensitivity"]
            )
            
            # Parse shareable content
            shareable_data = data.get("shareable_content", {})
            shareable_content = ShareableContent(
                open_topics=shareable_data.get("open_topics", []),
                conditional_sharing=shareable_data.get("conditional_sharing", [])
            )
            
            # Parse response behavior
            behavior_data = data.get("response_behavior", {})
            response_behavior = ResponseBehavior(
                direct_fact_queries=behavior_data.get("direct_fact_queries", {}),
                analytical_queries=behavior_data.get("analytical_queries", {}),
                creative_queries=behavior_data.get("creative_queries", {}),
                extraction_attempts=behavior_data.get("extraction_attempts", {})
            )
            
            # Parse privacy budget
            budget_data = data["privacy_budget"]
            privacy_budget = PrivacyBudget(
                total_entropy_budget=float(budget_data["total_entropy_budget"]),
                per_session_entropy_limit=float(budget_data["per_session_entropy_limit"]),
                daily_entropy_reset=budget_data.get("daily_entropy_reset", True),
                max_queries_per_hour=budget_data.get("max_queries_per_hour", 10),
                max_queries_per_day=budget_data.get("max_queries_per_day", 50),
                cooldown_period_minutes=budget_data.get("cooldown_period_minutes", 5),
                similarity_threshold=budget_data.get("similarity_threshold", 0.85),
                cumulative_similarity_limit=budget_data.get("cumulative_similarity_limit", 3.0),
                similarity_decay_hours=budget_data.get("similarity_decay_hours", 24)
            )
            
            # Parse multi-agent protection
            multiagent_data = data.get("multi_agent_protection", {})
            multi_agent_protection = MultiAgentProtection(
                global_budget_sharing=multiagent_data.get("global_budget_sharing", True),
                collective_entropy_limit=multiagent_data.get("collective_entropy_limit", 6.0),
                detect_coordinated_queries=multiagent_data.get("detect_coordinated_queries", True),
                coordination_similarity_threshold=multiagent_data.get("coordination_similarity_threshold", 0.9),
                coordination_time_window_hours=multiagent_data.get("coordination_time_window_hours", 48),
                diversify_responses=multiagent_data.get("diversify_responses", True),
                diversification_strategy=multiagent_data.get("diversification_strategy", "semantic_rotation")
            )
            
            # Parse security config
            security_data = data.get("security_config", {})
            security_config = SecurityConfig(
                require_signature=security_data.get("require_signature", True),
                signature_algorithm=security_data.get("signature_algorithm", "ed25519"),
                owner_public_key=security_data.get("owner_public_key", ""),
                integrity_checks=security_data.get("integrity_checks", True),
                checksum_algorithm=security_data.get("checksum_algorithm", "sha256"),
                audit_logging=security_data.get("audit_logging", True),
                log_all_queries=security_data.get("log_all_queries", True),
                log_all_responses=security_data.get("log_all_responses", True),
                log_privacy_violations=security_data.get("log_privacy_violations", True)
            )
            
            # Parse fallback config
            fallback_data = data.get("fallback_config", {})
            fallback_config = FallbackConfig(
                default_protection_level=fallback_data.get("default_protection_level", "high"),
                uncertainty_strategy=fallback_data.get("uncertainty_strategy", "err_on_privacy_side"),
                parsing_error_response=fallback_data.get("parsing_error_response", "Privacy settings prevent access."),
                budget_exceeded_response=fallback_data.get("budget_exceeded_response", "Information limit reached."),
                protection_violation_response=fallback_data.get("protection_violation_response", "This information is protected."),
                partial_failure_mode=fallback_data.get("partial_failure_mode", "abstract_only"),
                complete_failure_mode=fallback_data.get("complete_failure_mode", "refuse_all")
            )
            
            # Create instructions object
            instructions = PrivacyInstructions(
                schema_version=data["schema_version"],
                document_config=document_config,
                core_protected_content=data.get("core_protected_content", {}),
                shareable_content=shareable_content,
                response_behavior=response_behavior,
                privacy_budget=privacy_budget,
                multi_agent_protection=multi_agent_protection,
                security_config=security_config,
                fallback_config=fallback_config,
                metadata=data.get("metadata", {}),
                is_valid=True,
                file_hash=file_hash,
                loaded_from=file_path
            )
            
            # Parse protected facts and themes
            self._parse_protected_content(instructions)
            
            return instructions
            
        except Exception as e:
            logger.error(f"Error parsing instructions: {e}")
            return None
    
    def _parse_protected_content(self, instructions: PrivacyInstructions):
        """Parse protected facts and themes from core_protected_content."""
        try:
            protected_content = instructions.core_protected_content
            
            # Parse protected facts
            if "protected_facts" in protected_content:
                for fact_data in protected_content["protected_facts"]:
                    protected_fact = ProtectedFact(
                        category=fact_data["category"],
                        items=fact_data["items"],
                        protection_level=fact_data["protection_level"]
                    )
                    instructions.protected_facts.append(protected_fact)
            
            # Parse protected themes  
            if "protected_themes" in protected_content:
                for theme_data in protected_content["protected_themes"]:
                    protected_theme = ProtectedTheme(
                        theme=theme_data["theme"],
                        description=theme_data["description"],
                        abstraction_level=theme_data["abstraction_level"]
                    )
                    instructions.protected_themes.append(protected_theme)
                    
        except Exception as e:
            logger.error(f"Error parsing protected content: {e}")
            instructions.validation_errors.append(f"Failed to parse protected content: {e}")
    
    def get_instructions_for_document(self, document_name: str) -> Optional[PrivacyInstructions]:
        """Get privacy instructions for a specific document."""
        # First try exact match
        if document_name in self.loaded_instructions:
            return self.loaded_instructions[document_name]
        
        # Then try partial matches
        for doc_pattern, instructions in self.loaded_instructions.items():
            if doc_pattern in document_name or document_name in doc_pattern:
                logger.info(f"Using partial match instructions: {doc_pattern} for {document_name}")
                return instructions
        
        # Fall back to global defaults
        if self.global_defaults:
            logger.info(f"Using global default instructions for {document_name}")
            return self.global_defaults
        
        logger.warning(f"No privacy instructions found for document: {document_name}")
        return None
    
    def validate_instruction_integrity(self, instructions: PrivacyInstructions) -> bool:
        """Validate the integrity of loaded instructions."""
        if not instructions.loaded_from or not instructions.loaded_from.exists():
            return False
            
        try:
            # Re-read file and compare hash
            with open(instructions.loaded_from, 'r', encoding='utf-8') as f:
                current_content = f.read()
            
            current_hash = hashlib.sha256(current_content.encode('utf-8')).hexdigest()
            return current_hash == instructions.file_hash
            
        except Exception as e:
            logger.error(f"Error validating instruction integrity: {e}")
            return False