#!/usr/bin/env python3
"""
Privacy Budget Tracker

This module manages cumulative privacy budget tracking across sessions,
users, and time windows for the information-theoretic privacy filter system.

Key responsibilities:
- Track entropy consumption over time
- Enforce privacy budget limits
- Detect coordinated extraction attempts
- Manage session and global budget state
- Persist budget state across system restarts

Based on differential privacy and privacy budget research.
"""

import asyncio
import json
import logging
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
import hashlib

from entropy_calculator import EntropyCalculator, PrivacyBudgetState, EntropyMeasurement

logger = logging.getLogger(__name__)

@dataclass
class BudgetCheckResult:
    """Result of checking privacy budget constraints."""
    allowed: bool
    reason: str
    remaining_budget: float
    estimated_cost: float
    current_usage: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

@dataclass
class CoordinationAlert:
    """Alert about potential coordinated extraction attempts."""
    user_emails: List[str]
    document_name: str
    similarity_score: float
    time_window: timedelta
    query_patterns: List[str]
    risk_level: str  # "low", "medium", "high", "critical"
    detected_at: datetime = field(default_factory=datetime.now)

class PrivacyBudgetTracker:
    """
    Manages privacy budget consumption and enforcement across users and sessions.
    
    This tracker implements multi-dimensional privacy budget tracking:
    - Per-user daily/session limits
    - Per-document global limits
    - Coordinated query detection
    - Time-based budget decay and reset
    """
    
    def __init__(self, storage_path: Optional[Path] = None):
        """
        Initialize privacy budget tracker.
        
        Args:
            storage_path: Directory to persist budget state (None = memory only)
        """
        self.storage_path = storage_path
        self.entropy_calculator = EntropyCalculator()
        
        # Budget state tracking
        self.user_states: Dict[str, Dict[str, PrivacyBudgetState]] = defaultdict(dict)
        self.global_document_budgets: Dict[str, float] = {}
        
        # Coordination detection
        self.coordination_window_hours = 24
        self.coordination_threshold = 0.85
        self.coordination_alerts: List[CoordinationAlert] = []
        
        # Budget reset tracking
        self.last_daily_reset: Dict[str, datetime] = {}
        self.last_session_cleanup: datetime = datetime.now()
        
        # Performance caches
        self._budget_cache: Dict[str, Tuple[datetime, BudgetCheckResult]] = {}
        self._cache_ttl_seconds = 300  # 5 minute cache TTL
    
    async def initialize(self):
        """Initialize the budget tracker."""
        await self.entropy_calculator.initialize()
        
        if self.storage_path:
            await self._load_budget_state()
        
        logger.info("Privacy budget tracker initialized")
    
    async def check_budget_constraints(
        self,
        user_email: str,
        document_name: str,
        query: str,
        estimated_response_length: int = 200,
        session_id: Optional[str] = None,
        privacy_instructions: Optional[Any] = None
    ) -> BudgetCheckResult:
        """
        Check if a query is within privacy budget constraints.
        
        Args:
            user_email: Email of requesting user
            document_name: Name of document being queried
            query: The user's query
            estimated_response_length: Expected response length for budget estimation
            session_id: Session identifier
            privacy_instructions: Privacy rules for the document
            
        Returns:
            BudgetCheckResult indicating if query is allowed
        """
        # Check cache first
        cache_key = f"{user_email}:{document_name}:{hashlib.md5(query.encode()).hexdigest()[:8]}"
        if cache_key in self._budget_cache:
            cached_time, cached_result = self._budget_cache[cache_key]
            if (datetime.now() - cached_time).total_seconds() < self._cache_ttl_seconds:
                return cached_result
        
        try:
            # Get or create budget state
            state = await self._get_budget_state(user_email, document_name, session_id)
            
            # Perform daily reset if needed
            await self._check_daily_reset(user_email, state)
            
            # Estimate entropy cost of the query
            estimated_cost = self._estimate_query_cost(query, estimated_response_length, privacy_instructions)
            
            # Check various budget constraints
            constraints_result = await self._check_all_constraints(
                state, estimated_cost, document_name, privacy_instructions
            )
            
            if not constraints_result.allowed:
                # Cache negative result briefly
                self._budget_cache[cache_key] = (datetime.now(), constraints_result)
                return constraints_result
            
            # Check for coordination patterns
            coordination_result = await self._check_coordination_patterns(
                user_email, document_name, query, state
            )
            
            if coordination_result.warnings:
                constraints_result.warnings.extend(coordination_result.warnings)
            
            if not coordination_result.allowed:
                constraints_result.allowed = False
                constraints_result.reason = coordination_result.reason
            
            # Cache result
            self._budget_cache[cache_key] = (datetime.now(), constraints_result)
            
            return constraints_result
            
        except Exception as e:
            logger.error(f"Error checking budget constraints: {e}")
            return BudgetCheckResult(
                allowed=False,
                reason=f"Budget check error: {str(e)}",
                remaining_budget=0.0,
                estimated_cost=0.0
            )
    
    async def record_entropy_consumption(
        self,
        user_email: str,
        document_name: str,
        query: str,
        response: str,
        entropy_measurement: EntropyMeasurement,
        session_id: Optional[str] = None
    ):
        """
        Record actual entropy consumption after a query is processed.
        
        Args:
            user_email: Email of requesting user
            document_name: Document that was queried
            query: The original query
            response: The filtered response
            entropy_measurement: Measured entropy consumption
            session_id: Session identifier
        """
        try:
            # Get budget state
            state = await self._get_budget_state(user_email, document_name, session_id)
            
            # Update consumption
            state.total_entropy_consumed += entropy_measurement.entropy_value
            state.session_entropy_consumed += entropy_measurement.entropy_value
            state.total_queries += 1
            state.session_queries += 1
            state.last_query_time = datetime.now()
            
            # Update query/response history for similarity tracking
            state.query_history.append(query)
            state.response_history.append(response)
            
            # Limit history size
            max_history = 50
            if len(state.query_history) > max_history:
                state.query_history = state.query_history[-max_history:]
                state.response_history = state.response_history[-max_history:]
            
            # Update cumulative similarity
            if len(state.query_history) > 1:
                cumulative_sim = self.entropy_calculator.calculate_cumulative_similarity(
                    query, response,
                    state.query_history[:-1],  # All but the current query
                    state.response_history[:-1]
                )
                state.cumulative_similarity = cumulative_sim
            
            # Update global document budget
            if document_name not in self.global_document_budgets:
                self.global_document_budgets[document_name] = 0.0
            self.global_document_budgets[document_name] += entropy_measurement.entropy_value
            
            # Persist state if configured
            if self.storage_path:
                await self._save_budget_state()
            
            logger.debug(f"Recorded entropy consumption: {entropy_measurement.entropy_value:.3f} for {user_email}")
            
        except Exception as e:
            logger.error(f"Error recording entropy consumption: {e}")
    
    async def get_user_budget_summary(self, user_email: str) -> Dict[str, Any]:
        """Get comprehensive budget summary for a user."""
        user_documents = self.user_states.get(user_email, {})
        
        summary = {
            "user_email": user_email,
            "total_documents_accessed": len(user_documents),
            "last_activity": None,
            "documents": {}
        }
        
        total_entropy = 0.0
        total_queries = 0
        last_activity = None
        
        for doc_name, state in user_documents.items():
            doc_summary = {
                "entropy_consumed": state.total_entropy_consumed,
                "queries_made": state.total_queries,
                "session_entropy": state.session_entropy_consumed,
                "session_queries": state.session_queries,
                "first_query": state.first_query_time.isoformat() if state.first_query_time else None,
                "last_query": state.last_query_time.isoformat() if state.last_query_time else None,
                "cumulative_similarity": state.cumulative_similarity
            }
            
            summary["documents"][doc_name] = doc_summary
            total_entropy += state.total_entropy_consumed
            total_queries += state.total_queries
            
            if state.last_query_time:
                if not last_activity or state.last_query_time > last_activity:
                    last_activity = state.last_query_time
        
        summary.update({
            "total_entropy_consumed": total_entropy,
            "total_queries": total_queries,
            "last_activity": last_activity.isoformat() if last_activity else None
        })
        
        return summary
    
    async def detect_coordination_patterns(self, time_window_hours: int = 24) -> List[CoordinationAlert]:
        """
        Detect potential coordinated extraction attempts across users.
        
        Args:
            time_window_hours: Time window to analyze for coordination
            
        Returns:
            List of coordination alerts
        """
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(hours=time_window_hours)
        
        # Group queries by document and time window
        document_queries: Dict[str, List[Tuple[str, str, datetime]]] = defaultdict(list)
        
        for user_email, documents in self.user_states.items():
            for doc_name, state in documents.items():
                if state.last_query_time and state.last_query_time >= cutoff_time:
                    # Get recent queries
                    for i, query in enumerate(state.query_history[-10:]):  # Last 10 queries
                        query_time = state.last_query_time  # Simplified - would need proper timestamps
                        document_queries[doc_name].append((user_email, query, query_time))
        
        alerts = []
        
        for doc_name, queries in document_queries.items():
            if len(queries) < 2:
                continue
                
            # Check for similar queries across users
            for i, (user1, query1, time1) in enumerate(queries):
                for j, (user2, query2, time2) in enumerate(queries[i+1:], i+1):
                    if user1 == user2:
                        continue  # Same user
                    
                    # Calculate query similarity
                    similarity = self.entropy_calculator._calculate_text_similarity(query1, query2)
                    
                    if similarity >= self.coordination_threshold:
                        # Potential coordination detected
                        risk_level = "low"
                        if similarity >= 0.95:
                            risk_level = "critical"
                        elif similarity >= 0.90:
                            risk_level = "high"
                        elif similarity >= 0.85:
                            risk_level = "medium"
                        
                        alert = CoordinationAlert(
                            user_emails=[user1, user2],
                            document_name=doc_name,
                            similarity_score=similarity,
                            time_window=timedelta(hours=time_window_hours),
                            query_patterns=[query1, query2],
                            risk_level=risk_level
                        )
                        
                        alerts.append(alert)
        
        # Store alerts
        self.coordination_alerts.extend(alerts)
        
        return alerts
    
    async def _get_budget_state(
        self, 
        user_email: str, 
        document_name: str, 
        session_id: Optional[str]
    ) -> PrivacyBudgetState:
        """Get or create budget state for a user/document combination."""
        if document_name not in self.user_states[user_email]:
            # Create new budget state
            state = PrivacyBudgetState(
                user_email=user_email,
                session_id=session_id,
                document_name=document_name,
                first_query_time=datetime.now(),
                session_start_time=datetime.now()
            )
            self.user_states[user_email][document_name] = state
        else:
            state = self.user_states[user_email][document_name]
            
            # Update session info if provided
            if session_id and (not state.session_id or state.session_id != session_id):
                # New session started
                state.session_id = session_id
                state.session_start_time = datetime.now()
                state.session_entropy_consumed = 0.0
                state.session_queries = 0
        
        return state
    
    def _estimate_query_cost(
        self, 
        query: str, 
        estimated_response_length: int,
        privacy_instructions: Optional[Any]
    ) -> float:
        """
        Estimate entropy cost of a query before processing.
        
        This is a rough estimation used for budget checking.
        """
        # Base cost from query complexity
        query_entropy = self.entropy_calculator.calculate_shannon_entropy(query, "words")
        base_cost = query_entropy.entropy_value * 0.1
        
        # Estimated response cost (simplified)
        response_cost = estimated_response_length / 1000.0  # Rough scaling
        
        # Penalty for protected content mentions
        protection_penalty = 0.0
        if privacy_instructions:
            query_lower = query.lower()
            
            # Check for protected facts
            for fact in getattr(privacy_instructions, 'protected_facts', []):
                for item in fact.items:
                    if item.lower() in query_lower:
                        protection_penalty += 0.5
        
        estimated_cost = base_cost + response_cost + protection_penalty
        return max(0.1, estimated_cost)  # Minimum cost
    
    async def _check_all_constraints(
        self,
        state: PrivacyBudgetState,
        estimated_cost: float,
        document_name: str,
        privacy_instructions: Optional[Any]
    ) -> BudgetCheckResult:
        """Check all budget constraints for a query."""
        warnings = []
        
        if not privacy_instructions:
            return BudgetCheckResult(
                allowed=False,
                reason="No privacy instructions found",
                remaining_budget=0.0,
                estimated_cost=estimated_cost
            )
        
        budget_config = privacy_instructions.privacy_budget
        
        # Check session entropy limit
        if state.session_entropy_consumed + estimated_cost > budget_config.per_session_entropy_limit:
            return BudgetCheckResult(
                allowed=False,
                reason=f"Session entropy budget exceeded ({state.session_entropy_consumed + estimated_cost:.2f} > {budget_config.per_session_entropy_limit})",
                remaining_budget=max(0, budget_config.per_session_entropy_limit - state.session_entropy_consumed),
                estimated_cost=estimated_cost
            )
        
        # Check total entropy budget
        if state.total_entropy_consumed + estimated_cost > budget_config.total_entropy_budget:
            return BudgetCheckResult(
                allowed=False,
                reason=f"Total entropy budget exceeded ({state.total_entropy_consumed + estimated_cost:.2f} > {budget_config.total_entropy_budget})",
                remaining_budget=max(0, budget_config.total_entropy_budget - state.total_entropy_consumed),
                estimated_cost=estimated_cost
            )
        
        # Check daily query limits
        if state.total_queries >= budget_config.max_queries_per_day:
            return BudgetCheckResult(
                allowed=False,
                reason=f"Daily query limit exceeded ({state.total_queries} >= {budget_config.max_queries_per_day})",
                remaining_budget=budget_config.total_entropy_budget - state.total_entropy_consumed,
                estimated_cost=estimated_cost
            )
        
        # Check cumulative similarity threshold
        if (state.cumulative_similarity >= budget_config.cumulative_similarity_limit and 
            len(state.query_history) >= 3):
            warnings.append(f"High cumulative similarity detected: {state.cumulative_similarity:.2f}")
        
        # All constraints passed
        remaining_budget = min(
            budget_config.per_session_entropy_limit - state.session_entropy_consumed,
            budget_config.total_entropy_budget - state.total_entropy_consumed
        )
        
        return BudgetCheckResult(
            allowed=True,
            reason="Within budget constraints",
            remaining_budget=remaining_budget,
            estimated_cost=estimated_cost,
            current_usage={
                "session_entropy": state.session_entropy_consumed,
                "total_entropy": state.total_entropy_consumed,
                "session_queries": state.session_queries,
                "total_queries": state.total_queries
            },
            warnings=warnings
        )
    
    async def _check_coordination_patterns(
        self,
        user_email: str,
        document_name: str,
        query: str,
        state: PrivacyBudgetState
    ) -> BudgetCheckResult:
        """Check for coordination patterns in real-time."""
        # For now, just check cumulative similarity within user's own history
        if len(state.query_history) >= 5 and state.cumulative_similarity >= 0.9:
            return BudgetCheckResult(
                allowed=False,
                reason=f"Potential coordinated extraction detected (similarity: {state.cumulative_similarity:.2f})",
                remaining_budget=0.0,
                estimated_cost=0.0,
                warnings=[f"High query similarity pattern detected for user {user_email}"]
            )
        
        return BudgetCheckResult(
            allowed=True,
            reason="No coordination patterns detected",
            remaining_budget=0.0,
            estimated_cost=0.0
        )
    
    async def _check_daily_reset(self, user_email: str, state: PrivacyBudgetState):
        """Check if daily reset is needed and perform it."""
        current_time = datetime.now()
        last_reset = self.last_daily_reset.get(user_email)
        
        if not last_reset or (current_time - last_reset).days >= 1:
            # Perform daily reset
            state.total_queries = 0
            state.total_entropy_consumed = 0.0
            state.query_history.clear()
            state.response_history.clear()
            state.cumulative_similarity = 0.0
            
            self.last_daily_reset[user_email] = current_time
            logger.info(f"Performed daily reset for user: {user_email}")
    
    async def _load_budget_state(self):
        """Load budget state from persistent storage."""
        if not self.storage_path:
            return
        
        state_file = self.storage_path / "budget_state.json"
        if not state_file.exists():
            return
        
        try:
            with open(state_file, 'r') as f:
                data = json.load(f)
            
            # Reconstruct budget states
            for user_email, documents in data.get("user_states", {}).items():
                for doc_name, state_data in documents.items():
                    state = PrivacyBudgetState(**state_data)
                    # Convert timestamps back to datetime objects
                    if state_data.get("first_query_time"):
                        state.first_query_time = datetime.fromisoformat(state_data["first_query_time"])
                    if state_data.get("last_query_time"):
                        state.last_query_time = datetime.fromisoformat(state_data["last_query_time"])
                    if state_data.get("session_start_time"):
                        state.session_start_time = datetime.fromisoformat(state_data["session_start_time"])
                    
                    self.user_states[user_email][doc_name] = state
            
            # Load global budgets
            self.global_document_budgets.update(data.get("global_document_budgets", {}))
            
            logger.info(f"Loaded budget state from {state_file}")
            
        except Exception as e:
            logger.error(f"Error loading budget state: {e}")
    
    async def _save_budget_state(self):
        """Save budget state to persistent storage."""
        if not self.storage_path:
            return
        
        try:
            self.storage_path.mkdir(parents=True, exist_ok=True)
            
            # Prepare data for serialization
            data = {
                "user_states": {},
                "global_document_budgets": self.global_document_budgets,
                "last_updated": datetime.now().isoformat()
            }
            
            for user_email, documents in self.user_states.items():
                data["user_states"][user_email] = {}
                for doc_name, state in documents.items():
                    state_dict = asdict(state)
                    # Convert datetime objects to strings
                    for key, value in state_dict.items():
                        if isinstance(value, datetime):
                            state_dict[key] = value.isoformat()
                    
                    data["user_states"][user_email][doc_name] = state_dict
            
            state_file = self.storage_path / "budget_state.json"
            with open(state_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.debug(f"Saved budget state to {state_file}")
            
        except Exception as e:
            logger.error(f"Error saving budget state: {e}")