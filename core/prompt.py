#!/usr/bin/env python3
"""
Interactive CLI Prompt Module
"""

import sys
from typing import List, Dict, Optional
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from api.schemas import Vulnerability, Report
from core.cvss import CVSSCalculator

# Try to import questionary, fallback to simple input if not available
try:
    import questionary
    HAS_QUESTIONARY = True
except ImportError:
    HAS_QUESTIONARY = False
    print("⚠️ Questionary not installed. Using simple input mode.")
    print("   Install with: pip install questionary\n")


class ReportPrompt:
    """Interactive CLI prompt handler"""
    
    @staticmethod
    def simple_input(prompt: str, default: str = "", multiline: bool = False) -> str:
        """Fallback simple input when questionary is not available"""
        if default:
            prompt = f"{prompt} [{default}]: "
        else:
            prompt = f"{prompt}: "
        
        if multiline:
            print(prompt)
            print("(Enter blank line to finish)")
            lines = []
            while True:
                line = input()
                if not line:
                    break
                lines.append(line)
            result = "\n".join(lines)
        else:
            result = input(prompt)
        
        return result if result else default
    
    @staticmethod
    def ask_cvss() -> Optional[Dict]:
        """Ask user if they want to calculate CVSS score"""
        if HAS_QUESTIONARY:
            use_cvss = questionary.confirm(
                "📊 Calculate CVSS score for this vulnerability?",
                default=True
            ).ask()
        else:
            response = input("Calculate CVSS score? (y/n) [y]: ").lower()
            use_cvss = response != 'n'
        
        if use_cvss:
            return CVSSCalculator.interactive_input()
        return None
    
    @staticmethod
    def ask_steps_to_reproduce() -> List[str]:
        """Input steps to reproduce"""
        steps = []
        print("\n📝 Enter Steps to Reproduce:")
        print("   (Press Enter on empty line when done)\n")
        
        step_num = 1
        while True:
            if HAS_QUESTIONARY:
                step = questionary.text(f"Step {step_num}:").ask()
            else:
                step = input(f"Step {step_num}: ")
            
            if not step:
                break
            steps.append(step)
            step_num += 1
        
        if not steps:
            print("⚠️ No steps entered. Using default.")
            steps = ["No steps provided. Please add steps to reproduce."]
        
        return steps
    
    @staticmethod
    def ask_vulnerability() -> Vulnerability:
        """Input one vulnerability"""
        print("\n" + "="*60)
        print("🐛 NEW VULNERABILITY")
        print("="*60)
        
        # Title
        if HAS_QUESTIONARY:
            title = questionary.text(
                "Vulnerability Title:",
                validate=lambda text: len(text) >= 5 or "Minimal 5 characters"
            ).ask()
        else:
            title = ReportPrompt.simple_input("Vulnerability Title")
        
        if not title:
            title = "Untitled Vulnerability"
        
        # Description
        if HAS_QUESTIONARY:
            description = questionary.text(
                "Description:",
                multiline=True,
                validate=lambda text: len(text) >= 20 or "Minimal 20 characters"
            ).ask()
        else:
            description = ReportPrompt.simple_input("Description", multiline=True)
        
        if not description:
            description = "No description provided."
        
        # Steps
        steps = ReportPrompt.ask_steps_to_reproduce()
        
        # Impact
        if HAS_QUESTIONARY:
            impact = questionary.text("Impact/Business Impact:", multiline=True).ask()
        else:
            impact = ReportPrompt.simple_input("Impact", multiline=True)
        
        # PoC
        if HAS_QUESTIONARY:
            poc = questionary.text("Proof of Concept (optional):", multiline=True).ask()
        else:
            poc = ReportPrompt.simple_input("Proof of Concept", multiline=True)
        
        # CVSS
        cvss_data = ReportPrompt.ask_cvss()
        
        # Build vulnerability data
        vuln_data = {
            "title": title,
            "description": description,
            "steps_to_reproduce": steps,
            "impact": impact or "No impact description provided.",
            "poc": poc or "",
        }
        
        # Handle CVSS data - FIX: cvss_data is a dict, not tuple
        if cvss_data and isinstance(cvss_data, dict):
            vuln_data["cvss_score"] = cvss_data.get("score")
            vuln_data["cvss_vector"] = cvss_data.get("vector")
            vuln_data["severity"] = cvss_data.get("severity")
        
        return Vulnerability(**vuln_data)
    
    @staticmethod
    def create_report() -> Report:
        """Full interactive flow"""
        print("\n" + "="*60)
        print("🐞 BUG REPORT GENERATOR PRO v1.0")
        print("="*60)
        print("Generate professional security reports with ease\n")
        
        # Report metadata
        if HAS_QUESTIONARY:
            report_title = questionary.text(
                "Report Title:",
                default="Security Assessment Report",
                validate=lambda t: len(t) >= 5
            ).ask()
            
            author = questionary.text("Author Name:", default="Ruyynn").ask()
            target = questionary.text("Target URL/Application:", default="Not specified").ask()
            
            platform = questionary.select(
                "Select Platform:",
                choices=["hackerone", "bugcrowd", "intigriti", "custom"]
            ).ask()
        else:
            report_title = ReportPrompt.simple_input("Report Title", "Security Assessment Report")
            author = ReportPrompt.simple_input("Author Name", "Ruyynn")
            target = ReportPrompt.simple_input("Target URL/Application", "Not specified")
            
            print("\nSelect Platform:")
            print("  1. hackerone")
            print("  2. bugcrowd")
            print("  3. intigriti")
            print("  4. custom")
            platform_choice = input("Choice (1-4): ")
            platform_map = {"1": "hackerone", "2": "bugcrowd", "3": "intigriti", "4": "custom"}
            platform = platform_map.get(platform_choice, "hackerone")
        
        # Collect vulnerabilities
        vulnerabilities = []
        
        while True:
            vuln = ReportPrompt.ask_vulnerability()
            vulnerabilities.append(vuln)
            
            if HAS_QUESTIONARY:
                more = questionary.confirm(
                    f"\n✅ Added {len(vulnerabilities)} vulnerability(es). Add another?",
                    default=False
                ).ask()
            else:
                more_input = input(f"\nAdded {len(vulnerabilities)}. Add another? (y/n): ").lower()
                more = more_input == 'y'
            
            if not more:
                break
        
        # Create report
        report = Report(
            report_title=report_title,
            author=author,
            platform=platform,
            vulnerabilities=vulnerabilities,
            target=target
        )
        
        # Show summary
        summary = report.get_summary()
        
        print("\n" + "="*60)
        print("📊 REPORT SUMMARY")
        print("="*60)
        print(f"📝 Title: {report_title}")
        print(f"👤 Author: {author}")
        print(f"🎯 Target: {target}")
        print(f"📋 Platform: {platform}")
        print(f"🐛 Total Vulnerabilities: {summary['total_bugs']}")
        
        if summary['severity_breakdown']:
            print("\nSeverity Breakdown:")
            for sev, count in summary['severity_breakdown'].items():
                print(f"  • {sev.capitalize()}: {count}")
        
        if summary.get('avg_cvss', 0) > 0:
            print(f"\n📊 Average CVSS Score: {summary['avg_cvss']:.1f}")
        
        print("="*60)
        
        return report