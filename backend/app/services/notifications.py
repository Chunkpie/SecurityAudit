"""
Webhook Notifications — sends scan results to Slack, Discord, Teams, or custom webhooks.
"""
import logging

import httpx

logger = logging.getLogger(__name__)


async def send_webhook_notification(
    webhook_url: str,
    scan_result: dict,
    channel_type: str = "generic",
) -> bool:
    payload_builders = {
        "slack": _build_slack_payload,
        "discord": _build_discord_payload,
        "teams": _build_teams_payload,
        "generic": _build_generic_payload,
    }

    builder = payload_builders.get(channel_type, _build_generic_payload)
    payload = builder(scan_result)

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(webhook_url, json=payload)
            if resp.status_code not in (200, 201, 204):
                logger.warning(
                    f"Webhook returned {resp.status_code}: {resp.text[:200]}"
                )
                return False
            logger.info(f"Webhook notification sent to {channel_type}")
            return True
    except Exception as e:
        logger.error(f"Webhook notification failed: {e}")
        return False


def _build_slack_payload(result: dict) -> dict:
    verdict = result.get("verdict", "UNKNOWN")
    score = result.get("security_score", 0)
    color = "good" if verdict == "GO" else "warning" if verdict == "GO_WITH_CONDITIONS" else "danger"

    return {
        "attachments": [
            {
                "color": color,
                "title": f"SecAudit Scan Complete — {verdict}",
                "fields": [
                    {"title": "Security Score", "value": f"{score}/100", "short": True},
                    {"title": "Verdict", "value": verdict, "short": True},
                    {"title": "Total Findings", "value": str(result.get("metadata", {}).get("total_findings", 0)), "short": True},
                ],
                "footer": "SecAudit Security Platform",
            }
        ]
    }


def _build_discord_payload(result: dict) -> dict:
    verdict = result.get("verdict", "UNKNOWN")
    score = result.get("security_score", 0)
    color = 65280 if verdict == "GO" else 16776960 if verdict == "GO_WITH_CONDITIONS" else 16711680

    return {
        "embeds": [
            {
                "title": f"SecAudit Scan Complete — {verdict}",
                "color": color,
                "fields": [
                    {"name": "Security Score", "value": f"{score}/100", "inline": True},
                    {"name": "Verdict", "value": verdict, "inline": True},
                    {"name": "Findings", "value": str(result.get("metadata", {}).get("total_findings", 0)), "inline": True},
                ],
            }
        ]
    }


def _build_teams_payload(result: dict) -> dict:
    verdict = result.get("verdict", "UNKNOWN")
    score = result.get("security_score", 0)

    return {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "0078D7",
        "summary": f"SecAudit Scan: {verdict}",
        "sections": [
            {
                "activityTitle": f"SecAudit Scan Result — {verdict}",
                "facts": [
                    {"name": "Score", "value": f"{score}/100"},
                    {"name": "Verdict", "value": verdict},
                    {"name": "Findings", "value": str(result.get("metadata", {}).get("total_findings", 0))},
                ],
            }
        ],
    }


def _build_generic_payload(result: dict) -> dict:
    return {
        "event": "scan_completed",
        "verdict": result.get("verdict"),
        "security_score": result.get("security_score"),
        "total_findings": result.get("metadata", {}).get("total_findings", 0),
        "timestamp": result.get("metadata", {}).get("scan_duration_seconds"),
    }
