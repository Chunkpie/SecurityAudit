"""
Context-Aware Suppression Rules — allows organizations to define rules that auto-dismiss known false positives.
"""
import logging
import re
from typing import List, Optional

logger = logging.getLogger(__name__)


class SuppressionRule:
    def __init__(
        self,
        rule_type: str,
        pattern: str,
        finding_title_pattern: str = "",
        severity: str = "",
        enabled: bool = True,
    ):
        if rule_type not in ("path", "header", "body", "scanner", "finding_id"):
            raise ValueError(f"Invalid rule_type: {rule_type}")
        self.rule_type = rule_type
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.finding_title_pattern = (
            re.compile(finding_title_pattern, re.IGNORECASE)
            if finding_title_pattern
            else None
        )
        self.severity = severity
        self.enabled = enabled

    def matches(self, finding: dict) -> bool:
        if not self.enabled:
            return False

        if self.finding_title_pattern and not self.finding_title_pattern.search(
            finding.get("title", "")
        ):
            return False

        if self.severity and finding.get("severity", "") != self.severity:
            return False

        if self.rule_type == "path":
            url = finding.get("affected_url", "")
            return bool(self.pattern.search(url))

        elif self.rule_type == "header":
            evidence = finding.get("evidence", {})
            if isinstance(evidence, dict):
                for key, value in evidence.items():
                    if isinstance(value, str) and self.pattern.search(value):
                        return True
            return False

        elif self.rule_type == "body":
            evidence = finding.get("evidence", {})
            if isinstance(evidence, dict):
                for key, value in evidence.items():
                    if isinstance(value, str) and self.pattern.search(value):
                        return True
                    if isinstance(value, dict):
                        for v in value.values():
                            if isinstance(v, str) and self.pattern.search(v):
                                return True
            return False

        elif self.rule_type == "scanner":
            tool = finding.get("tool_name", "")
            return bool(self.pattern.search(tool))

        elif self.rule_type == "finding_id":
            finding_id = finding.get("cve_ids", [])
            return any(self.pattern.search(str(cve)) for cve in finding_id)

        return False


def apply_suppression_rules(
    findings: List[dict],
    rules: List[SuppressionRule],
) -> List[dict]:
    if not rules:
        return findings

    filtered = []
    suppressed_count = 0

    for finding in findings:
        is_suppressed = any(rule.matches(finding) for rule in rules)
        if is_suppressed:
            suppressed_count += 1
            logger.debug(
                f"Suppressed finding: {finding.get('title')} "
                f"(severity={finding.get('severity')})"
            )
            finding["is_suppressed"] = True
            finding["correlation_status"] = "suppressed"
            filtered.append(finding)
        else:
            filtered.append(finding)

    if suppressed_count > 0:
        logger.info(f"Suppressed {suppressed_count} findings via suppression rules")

    return filtered
