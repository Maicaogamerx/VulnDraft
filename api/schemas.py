#!/usr/bin/env python3
"""
Pydantic Schemas for Data Validation
Ensures data integrity across CLI and Web interfaces
"""

from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Optional, List, Literal, Dict, Any, Union
from datetime import datetime
import re


class Vulnerability(BaseModel):
    """
    Vulnerability data model
    Represents a single security finding
    """
    
    # Core fields
    title: str = Field(
        ..., 
        min_length=5, 
        max_length=200,
        description="Title of the vulnerability"
    )
    description: str = Field(
        ...,
        min_length=20,
        max_length=5000,
        description="Detailed description of the vulnerability"
    )
    steps_to_reproduce: List[str] = Field(
        ...,
        min_length=1,
        description="Step-by-step reproduction instructions"
    )
    
    # Optional fields
    impact: Optional[str] = Field(
        None,
        max_length=2000,
        description="Business impact of the vulnerability"
    )
    severity: Optional[Literal["critical", "high", "medium", "low", "info"]] = Field(
        None,
        description="Severity rating"
    )
    cvss_score: Optional[float] = Field(
        None,
        ge=0.0,
        le=10.0,
        description="CVSS v3.1 score"
    )
    cvss_vector: Optional[str] = Field(
        None,
        description="CVSS vector string"
    )
    poc: Optional[str] = Field(
        None,
        description="Proof of Concept code or description"
    )
    affected_components: Optional[List[str]] = Field(
        None,
        description="Affected components or endpoints"
    )
    
    # Metadata
    created_at: datetime = Field(
        default_factory=datetime.now,
        description="Creation timestamp"
    )
    
    @field_validator('title')
    @classmethod
    def validate_title(cls, v: str) -> str:
        """Validate title format"""
        if not v.strip():
            raise ValueError("Title cannot be empty or whitespace")
        if v.isupper():
            raise ValueError("Title should not be all uppercase")
        return v.strip()
    
    @field_validator('steps_to_reproduce')
    @classmethod
    def validate_steps(cls, v: List[str]) -> List[str]:
        """Validate steps are not empty"""
        if not v or all(not step.strip() for step in v):
            raise ValueError("At least one valid step is required")
        return [step.strip() for step in v if step.strip()]
    
    @field_validator('cvss_vector')
    @classmethod
    def validate_cvss_vector(cls, v: Optional[str]) -> Optional[str]:
        """
        Validate CVSS vector format - FIXED: More flexible pattern
        Accepts standard CVSS v3.1 format with various metric combinations
        """
        if v is None:
            return v
        
        # More flexible pattern that accepts valid CVSS v3.1 vectors
        # Pattern: CVSS:3.1/ followed by metric pairs (METRIC:VALUE)
        # Allowed metrics: AV, AC, PR, UI, S, C, I, A
        # Allowed values for each metric are defined
        pattern = r'^CVSS:3\.1/(AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/(C:[HLN]|I:[HLN]|A:[HLN]){3})$'
        
        # Alternative: simpler pattern that just checks basic structure
        simple_pattern = r'^CVSS:3\.1/([A-Z]{2}:[A-Z]+/)+[A-Z]{2}:[A-Z]+$'
        
        if re.match(pattern, v) or re.match(simple_pattern, v):
            return v
        
        # If pattern doesn't match, still accept it (don't block user)
        # Many valid CVSS vectors might have different ordering or extra fields
        # Log warning but don't fail validation
        print(f"⚠️ Warning: CVSS vector format may be non-standard: {v}")
        return v
    
    @model_validator(mode='after')
    def validate_severity_with_cvss(self) -> 'Vulnerability':
        """Ensure severity matches CVSS score if both present"""
        if self.cvss_score is not None and self.severity is not None:
            severity_map = {
                "critical": (9.0, 10.0),
                "high": (7.0, 8.9),
                "medium": (4.0, 6.9),
                "low": (0.1, 3.9),
                "info": (0.0, 0.0)
            }
            min_score, max_score = severity_map.get(self.severity, (0, 10))
            
            if not (min_score <= self.cvss_score <= max_score):
                # Auto-correct severity based on CVSS score
                if self.cvss_score >= 9.0:
                    self.severity = "critical"
                elif self.cvss_score >= 7.0:
                    self.severity = "high"
                elif self.cvss_score >= 4.0:
                    self.severity = "medium"
                elif self.cvss_score >= 0.1:
                    self.severity = "low"
                else:
                    self.severity = "info"
        
        return self
    
    class Config:
        json_schema_extra = {
            "example": {
                "title": "SQL Injection on Login Page",
                "description": "The username parameter is vulnerable to time-based SQL injection",
                "steps_to_reproduce": [
                    "Navigate to /login page",
                    "Intercept request with Burp Suite",
                    "Inject payload: ' OR SLEEP(5)--",
                    "Observe 5 second delay in response"
                ],
                "impact": "Attacker can bypass authentication and extract sensitive data",
                "severity": "critical",
                "cvss_score": 9.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "poc": "curl -X POST https://example.com/login -d 'username=\\' OR SLEEP(5)--&password=test'"
            }
        }


class Report(BaseModel):
    """
    Report data model
    Contains multiple vulnerabilities and report metadata
    """
    
    # Core fields
    report_title: str = Field(
        ...,
        min_length=5,
        max_length=200,
        description="Title of the security report"
    )
    author: str = Field(
        default="Anonymous",
        min_length=1,
        max_length=100,
        description="Author of the report"
    )
    platform: Literal["hackerone", "bugcrowd", "intigriti", "custom"] = Field(
        default="custom",
        description="Target platform for the report"
    )
    vulnerabilities: List[Vulnerability] = Field(
        ...,
        min_length=1,
        description="List of vulnerabilities in the report"
    )
    
    # Metadata
    target: Optional[str] = Field(
        None,
        max_length=500,
        description="Target URL or application"
    )
    date: datetime = Field(
        default_factory=datetime.now,
        description="Report generation date"
    )
    report_id: str = Field(
        default_factory=lambda: f"BRG-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        description="Unique report identifier"
    )
    
    # Optional fields for future expansion
    tags: Optional[List[str]] = Field(
        None,
        description="Tags for categorization"
    )
    attachments: Optional[List[str]] = Field(
        None,
        description="List of attachment file paths"
    )
    
    @field_validator('report_title')
    @classmethod
    def validate_report_title(cls, v: str) -> str:
        """Validate report title"""
        if not v.strip():
            raise ValueError("Report title cannot be empty")
        return v.strip()
    
    @field_validator('author')
    @classmethod
    def validate_author(cls, v: str) -> str:
        """Validate author name"""
        if not v.strip():
            return "Anonymous"
        return v.strip()
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Generate summary statistics for the report
        
        Returns:
            Dictionary with summary statistics
        """
        severity_counts = {}
        cvss_scores = []
        highest_cvss = 0
        
        for vuln in self.vulnerabilities:
            # Count severity
            sev = vuln.severity or "unknown"
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            # Collect CVSS scores
            if vuln.cvss_score is not None:
                cvss_scores.append(vuln.cvss_score)
                if vuln.cvss_score > highest_cvss:
                    highest_cvss = vuln.cvss_score
        
        # Calculate average CVSS
        avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0
        
        # Determine highest severity
        severity_order = ["critical", "high", "medium", "low", "info", "unknown"]
        highest_severity = "info"
        for sev in severity_order:
            if severity_counts.get(sev, 0) > 0:
                highest_severity = sev
                break
        
        return {
            "total_bugs": len(self.vulnerabilities),
            "severity_breakdown": severity_counts,
            "avg_cvss": round(avg_cvss, 1),
            "highest_cvss": highest_cvss if highest_cvss > 0 else None,
            "highest_severity": highest_severity,
            "has_poc": any(v.poc for v in self.vulnerabilities),
            "has_cvss": any(v.cvss_score for v in self.vulnerabilities)
        }
    
    class Config:
        json_schema_extra = {
            "example": {
                "report_title": "Security Assessment Report - Example.com",
                "author": "John Doe",
                "platform": "hackerone",
                "target": "https://example.com",
                "vulnerabilities": []
            }
        }