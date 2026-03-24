#!/usr/bin/env python3
"""
CVSS v3.1 Calculator Module
Implementation based on FIRST.org CVSS v3.1 specification
"""

from typing import Dict, Tuple, Optional, Union
from dataclasses import dataclass
from enum import Enum


class AttackVector(Enum):
    """Attack Vector (AV) metric"""
    NETWORK = ("N", "Network", 0.85)
    ADJACENT = ("A", "Adjacent Network", 0.62)
    LOCAL = ("L", "Local", 0.55)
    PHYSICAL = ("P", "Physical", 0.2)
    
    def __new__(cls, code, name, value):
        obj = object.__new__(cls)
        obj._code = code
        obj._name = name
        obj._value = value
        return obj
    
    @property
    def code(self):
        return self._code
    
    @property
    def metric_name(self):
        return self._name
    
    @property
    def metric_value(self):
        return self._value


class AttackComplexity(Enum):
    """Attack Complexity (AC) metric"""
    LOW = ("L", "Low", 0.77)
    HIGH = ("H", "High", 0.44)
    
    def __new__(cls, code, name, value):
        obj = object.__new__(cls)
        obj._code = code
        obj._name = name
        obj._value = value
        return obj
    
    @property
    def code(self):
        return self._code
    
    @property
    def metric_name(self):
        return self._name
    
    @property
    def metric_value(self):
        return self._value


class PrivilegesRequired(Enum):
    """Privileges Required (PR) metric"""
    NONE = ("N", "None", 0.85)
    LOW = ("L", "Low", 0.62)
    HIGH = ("H", "High", 0.27)
    
    def __new__(cls, code, name, value):
        obj = object.__new__(cls)
        obj._code = code
        obj._name = name
        obj._value = value
        return obj
    
    @property
    def code(self):
        return self._code
    
    @property
    def metric_name(self):
        return self._name
    
    @property
    def metric_value(self):
        return self._value


class UserInteraction(Enum):
    """User Interaction (UI) metric"""
    NONE = ("N", "None", 0.85)
    REQUIRED = ("R", "Required", 0.62)
    
    def __new__(cls, code, name, value):
        obj = object.__new__(cls)
        obj._code = code
        obj._name = name
        obj._value = value
        return obj
    
    @property
    def code(self):
        return self._code
    
    @property
    def metric_name(self):
        return self._name
    
    @property
    def metric_value(self):
        return self._value


class Scope(Enum):
    """Scope (S) metric"""
    UNCHANGED = ("U", "Unchanged", 0)
    CHANGED = ("C", "Changed", 1.08)
    
    def __new__(cls, code, name, value):
        obj = object.__new__(cls)
        obj._code = code
        obj._name = name
        obj._value = value
        return obj
    
    @property
    def code(self):
        return self._code
    
    @property
    def metric_name(self):
        return self._name
    
    @property
    def metric_value(self):
        return self._value


class Impact(Enum):
    """Impact metrics (C, I, A)"""
    HIGH = ("H", "High", 0.56)
    LOW = ("L", "Low", 0.22)
    NONE = ("N", "None", 0)
    
    def __new__(cls, code, name, value):
        obj = object.__new__(cls)
        obj._code = code
        obj._name = name
        obj._value = value
        return obj
    
    @property
    def code(self):
        return self._code
    
    @property
    def metric_name(self):
        return self._name
    
    @property
    def metric_value(self):
        return self._value


@dataclass
class CVSSMetrics:
    """Container for CVSS metrics"""
    attack_vector: AttackVector
    attack_complexity: AttackComplexity
    privileges_required: PrivilegesRequired
    user_interaction: UserInteraction
    scope: Scope
    confidentiality: Impact
    integrity: Impact
    availability: Impact
    
    def to_vector_string(self) -> str:
        """Convert metrics to CVSS vector string"""
        return f"CVSS:3.1/AV:{self.attack_vector.code}/AC:{self.attack_complexity.code}/PR:{self.privileges_required.code}/UI:{self.user_interaction.code}/S:{self.scope.code}/C:{self.confidentiality.code}/I:{self.integrity.code}/A:{self.availability.code}"


class CVSSCalculator:
    """
    CVSS v3.1 Calculator
    """
    
    @staticmethod
    def calculate_iss(metrics: CVSSMetrics) -> float:
        """Calculate Impact Sub-Score (ISS)"""
        c_value = metrics.confidentiality.metric_value
        i_value = metrics.integrity.metric_value
        a_value = metrics.availability.metric_value
        return 1 - ((1 - c_value) * (1 - i_value) * (1 - a_value))
    
    @staticmethod
    def calculate_impact(iss: float, scope: Scope) -> float:
        """Calculate Impact Score"""
        if scope == Scope.UNCHANGED:
            return 6.42 * iss
        else:
            return 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    
    @staticmethod
    def calculate_exploitability(metrics: CVSSMetrics) -> float:
        """Calculate Exploitability Score"""
        return (8.22 * 
                metrics.attack_vector.metric_value * 
                metrics.attack_complexity.metric_value * 
                metrics.privileges_required.metric_value * 
                metrics.user_interaction.metric_value)
    
    @staticmethod
    def calculate_base_score(impact: float, exploitability: float, scope: Scope) -> float:
        """Calculate Base Score"""
        if impact <= 0:
            return 0.0
        
        if scope == Scope.UNCHANGED:
            base_score = impact + exploitability
        else:
            base_score = 1.08 * (impact + exploitability)
        
        return round(min(base_score, 10.0), 1)
    
    @classmethod
    def calculate_score(cls, metrics: CVSSMetrics) -> Tuple[float, str]:
        """Calculate full CVSS score"""
        iss = cls.calculate_iss(metrics)
        impact = cls.calculate_impact(iss, metrics.scope)
        exploitability = cls.calculate_exploitability(metrics)
        base_score = cls.calculate_base_score(impact, exploitability, metrics.scope)
        vector_string = metrics.to_vector_string()
        
        return base_score, vector_string
    
    @classmethod
    def get_severity_rating(cls, score: float) -> str:
        """Convert CVSS score to severity rating"""
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score >= 0.1:
            return "Low"
        else:
            return "Info"
    
    @classmethod
    def interactive_input(cls) -> Optional[Dict[str, Union[float, str]]]:
        """
        Interactive CLI input for CVSS metrics
        Returns dict with score, vector, severity
        """
        print("\n" + "="*60)
        print("📊 CVSS v3.1 CALCULATOR")
        print("="*60)
        print("Answer the following questions to calculate CVSS score:\n")
        
        try:
            # Attack Vector
            print("\n1. Attack Vector (AV):")
            print("   [N] Network - Remotely exploitable")
            print("   [A] Adjacent Network - Same network segment")
            print("   [L] Local - Requires local access")
            print("   [P] Physical - Requires physical access")
            av_choice = input("Choice (N/A/L/P): ").upper()
            av_map = {
                "N": AttackVector.NETWORK, 
                "A": AttackVector.ADJACENT, 
                "L": AttackVector.LOCAL, 
                "P": AttackVector.PHYSICAL
            }
            attack_vector = av_map.get(av_choice, AttackVector.NETWORK)
            
            # Attack Complexity
            print("\n2. Attack Complexity (AC):")
            print("   [L] Low - Easy to exploit")
            print("   [H] High - Special conditions required")
            ac_choice = input("Choice (L/H): ").upper()
            attack_complexity = AttackComplexity.LOW if ac_choice == "L" else AttackComplexity.HIGH
            
            # Privileges Required
            print("\n3. Privileges Required (PR):")
            print("   [N] None - No privileges required")
            print("   [L] Low - Basic user privileges")
            print("   [H] High - Administrator privileges")
            pr_choice = input("Choice (N/L/H): ").upper()
            pr_map = {
                "N": PrivilegesRequired.NONE, 
                "L": PrivilegesRequired.LOW, 
                "H": PrivilegesRequired.HIGH
            }
            privileges_required = pr_map.get(pr_choice, PrivilegesRequired.NONE)
            
            # User Interaction
            print("\n4. User Interaction (UI):")
            print("   [N] None - No user interaction required")
            print("   [R] Required - Requires user action")
            ui_choice = input("Choice (N/R): ").upper()
            user_interaction = UserInteraction.NONE if ui_choice == "N" else UserInteraction.REQUIRED
            
            # Scope
            print("\n5. Scope (S):")
            print("   [U] Unchanged - Vulnerable component affected")
            print("   [C] Changed - Other components affected")
            s_choice = input("Choice (U/C): ").upper()
            scope = Scope.UNCHANGED if s_choice == "U" else Scope.CHANGED
            
            # Confidentiality Impact
            print("\n6. Confidentiality Impact (C):")
            print("   [H] High - Complete compromise")
            print("   [L] Low - Limited impact")
            print("   [N] None - No impact")
            c_choice = input("Choice (H/L/N): ").upper()
            c_map = {"H": Impact.HIGH, "L": Impact.LOW, "N": Impact.NONE}
            confidentiality = c_map.get(c_choice, Impact.NONE)
            
            # Integrity Impact
            print("\n7. Integrity Impact (I):")
            print("   [H] High - Complete compromise")
            print("   [L] Low - Limited impact")
            print("   [N] None - No impact")
            i_choice = input("Choice (H/L/N): ").upper()
            integrity = c_map.get(i_choice, Impact.NONE)
            
            # Availability Impact
            print("\n8. Availability Impact (A):")
            print("   [H] High - Complete compromise")
            print("   [L] Low - Limited impact")
            print("   [N] None - No impact")
            a_choice = input("Choice (H/L/N): ").upper()
            availability = c_map.get(a_choice, Impact.NONE)
            
            # Create metrics object
            metrics = CVSSMetrics(
                attack_vector=attack_vector,
                attack_complexity=attack_complexity,
                privileges_required=privileges_required,
                user_interaction=user_interaction,
                scope=scope,
                confidentiality=confidentiality,
                integrity=integrity,
                availability=availability
            )
            
            # Calculate score
            score, vector = cls.calculate_score(metrics)
            severity = cls.get_severity_rating(score)
            
            print(f"\n{'='*60}")
            print(f"✅ CVSS Score: {score} ({severity})")
            print(f"📋 Vector: {vector}")
            print(f"{'='*60}\n")
            
            # Return dictionary with proper types
            return {
                "score": float(score),
                "vector": str(vector),
                "severity": str(severity).lower()
            }
            
        except KeyboardInterrupt:
            print("\n\n⚠️ CVSS calculation cancelled")
            return None
        except Exception as e:
            print(f"\n❌ Error calculating CVSS: {e}")
            return None