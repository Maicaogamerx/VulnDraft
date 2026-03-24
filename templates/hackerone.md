# {{ report_title }}

**Report ID:** {{ report_id }}  
**Date:** {{ date }}  
**Author:** {{ author }}  
**Target:** {{ target if target else 'Not specified' }}

---

## Summary

This report documents security findings discovered during security assessment of {{ target if target else 'the target application' }}.

| Metric | Value |
|--------|-------|
| Total Vulnerabilities | {{ summary.total_bugs }} |
| Highest Severity | {{ summary.highest_severity | upper }} |
{% if summary.avg_cvss > 0 %}| Average CVSS Score | {{ summary.avg_cvss }} |{% endif %}

---

## Vulnerability Details

{% for vuln in vulnerabilities %}
### {{ vuln.id }}. {{ vuln.title }}

| Field | Details |
|-------|---------|
| **Severity** | {% if vuln.severity %}{{ vuln.severity | upper }}{% else %}Not Rated{% endif %} |
{% if vuln.cvss_score %}| **CVSS Score** | {{ vuln.cvss_score }} ({{ vuln.cvss_vector }}) |{% endif %}
| **Affected Component** | {{ vuln.affected_components | join(', ') if vuln.affected_components else 'Not specified' }} |

#### Description
{{ vuln.description }}

#### Steps to Reproduce
{% for step in vuln.steps_to_reproduce %}
{{ loop.index }}. {{ step }}
{% endfor %}

#### Impact
{{ vuln.impact if vuln.impact else 'No impact description provided.' }}

{% if vuln.poc %}
#### Proof of Concept
{{ vuln.poc }}

{% endif %}

#### Recommendation
Please refer to the OWASP guidelines for remediation of this vulnerability type.

---

{% endfor %}

## Additional Information

### Testing Methodology
- All testing was conducted within the defined scope
- No production data was accessed or modified
- All findings were validated to eliminate false positives

### Disclosure Timeline
- **Discovery:** {{ date }}
- **Report Generated:** {{ metadata.generated_at }}

### Contact
For questions regarding this report, please contact {{ author }}.

---

*This report was generated using VulnDraft v{{ metadata.version }}*
*© {{ metadata.generated_at[:4] }} {{ author }}. All rights reserved.*