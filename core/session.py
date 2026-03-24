#!/usr/bin/env python3
"""
Session Manager Module
Handles multi-bug sessions and temporary storage
"""

import json
import tempfile
import pickle
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List
import uuid

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from api.schemas import Report, Vulnerability


class SessionManager:
    """
    Manages report sessions for multi-bug workflows
    Supports save/load/resume functionality
    """
    
    def __init__(self, session_dir: Optional[Path] = None):
        """
        Initialize session manager
        
        Args:
            session_dir: Directory to store sessions (default: temp dir)
        """
        if session_dir:
            self.session_dir = Path(session_dir)
        else:
            self.session_dir = Path(tempfile.gettempdir()) / "bug_report_gen"
        
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.current_session: Optional[Dict[str, Any]] = None
        self.session_id: Optional[str] = None
    
    def create_session(self, report_title: str, author: str) -> str:
        """
        Create a new session
        
        Args:
            report_title: Title of the report
            author: Author name
            
        Returns:
            Session ID
        """
        self.session_id = str(uuid.uuid4())[:8]
        self.current_session = {
            "session_id": self.session_id,
            "report_title": report_title,
            "author": author,
            "vulnerabilities": [],
            "created_at": datetime.now().isoformat(),
            "last_modified": datetime.now().isoformat(),
            "metadata": {
                "target": None,
                "platform": "hackerone"
            }
        }
        
        self._save_session()
        return self.session_id
    
    def add_vulnerability(self, vulnerability: Vulnerability) -> None:
        """
        Add vulnerability to current session
        
        Args:
            vulnerability: Vulnerability object to add
        """
        if not self.current_session:
            raise ValueError("No active session. Create a session first.")
        
        vuln_dict = vulnerability.model_dump()
        vuln_dict["created_at"] = datetime.now().isoformat()
        self.current_session["vulnerabilities"].append(vuln_dict)
        self.current_session["last_modified"] = datetime.now().isoformat()
        self._save_session()
    
    def update_metadata(self, key: str, value: Any) -> None:
        """
        Update session metadata
        
        Args:
            key: Metadata key
            value: Metadata value
        """
        if self.current_session:
            self.current_session["metadata"][key] = value
            self.current_session["last_modified"] = datetime.now().isoformat()
            self._save_session()
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Load a session by ID
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session data or None if not found
        """
        session_file = self.session_dir / f"{session_id}.json"
        
        if session_file.exists():
            with open(session_file, 'r') as f:
                return json.load(f)
        
        return None
    
    def list_sessions(self) -> List[Dict[str, Any]]:
        """
        List all available sessions
        
        Returns:
            List of session summaries
        """
        sessions = []
        
        for session_file in self.session_dir.glob("*.json"):
            try:
                with open(session_file, 'r') as f:
                    data = json.load(f)
                    sessions.append({
                        "session_id": data.get("session_id"),
                        "report_title": data.get("report_title"),
                        "created_at": data.get("created_at"),
                        "vulnerability_count": len(data.get("vulnerabilities", []))
                    })
            except Exception:
                continue
        
        return sorted(sessions, key=lambda x: x.get("created_at", ""), reverse=True)
    
    def delete_session(self, session_id: str) -> bool:
        """
        Delete a session
        
        Args:
            session_id: Session identifier
            
        Returns:
            True if deleted, False otherwise
        """
        session_file = self.session_dir / f"{session_id}.json"
        
        if session_file.exists():
            session_file.unlink()
            return True
        
        return False
    
    def resume_session(self, session_id: str) -> bool:
        """
        Resume a previous session
        
        Args:
            session_id: Session identifier
            
        Returns:
            True if resumed successfully
        """
        session_data = self.get_session(session_id)
        
        if session_data:
            self.session_id = session_id
            self.current_session = session_data
            return True
        
        return False
    
    def _save_session(self) -> None:
        """Save current session to disk"""
        if self.current_session and self.session_id:
            session_file = self.session_dir / f"{self.session_id}.json"
            with open(session_file, 'w') as f:
                json.dump(self.current_session, f, indent=2, default=str)
    
    def get_report_from_session(self) -> Report:
        """
        Convert current session to Report object
        
        Returns:
            Report object
        """
        if not self.current_session:
            raise ValueError("No active session")
        
        # Convert vulnerability dicts back to Vulnerability objects
        vulnerabilities = []
        for vuln_dict in self.current_session["vulnerabilities"]:
            # Convert date strings back to datetime
            if "created_at" in vuln_dict:
                vuln_dict["created_at"] = datetime.fromisoformat(vuln_dict["created_at"])
            vulnerabilities.append(Vulnerability(**vuln_dict))
        
        # Create Report
        report = Report(
            report_title=self.current_session["report_title"],
            author=self.current_session["author"],
            platform=self.current_session["metadata"].get("platform", "hackerone"),
            vulnerabilities=vulnerabilities,
            target=self.current_session["metadata"].get("target")
        )
        
        return report
    
    def clear_current_session(self) -> None:
        """Clear current session without deleting file"""
        self.current_session = None
        self.session_id = None