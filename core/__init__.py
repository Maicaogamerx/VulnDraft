"""
Core module for Bug Report Generator
Contains business logic and core functionality
"""

from core.cvss import CVSSCalculator
from core.prompt import ReportPrompt
from core.builder import ReportBuilder
from core.session import SessionManager

__all__ = [
    'CVSSCalculator',
    'ReportPrompt', 
    'ReportBuilder',
    'SessionManager'
]