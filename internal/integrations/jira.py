import httpx
import json
from internal.integrations.base import Integration


class JiraIntegration(Integration):
    name = "jira"

    async def create_issue(self, config: dict, finding: dict) -> dict | None:
        try:
            base_url = config["url"].rstrip("/")
            project = config["project"]
            email = config["email"]
            token = config["token"]

            severity = finding.get("severity", "medium")
            priority_map = {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low"}
            priority = priority_map.get(severity, "Medium")

            issue_data = {
                "fields": {
                    "project": {"key": project},
                    "summary": finding.get("title", "ASM Finding"),
                    "description": f"*ASM Finding*\n\nType: {finding.get('type', 'N/A')}\n"
                                   f"Asset: {finding.get('value', 'N/A')}\n"
                                   f"Severity: {severity}\n\n"
                                   f"Details:\n{finding.get('details', 'N/A')}",
                    "issuetype": {"name": "Bug"},
                    "priority": {"name": priority},
                }
            }

            async with httpx.AsyncClient(timeout=15, auth=(email, token)) as client:
                resp = await client.post(
                    f"{base_url}/rest/api/2/issue",
                    json=issue_data,
                )
                if resp.status_code in (200, 201):
                    key = resp.json().get("key")
                    return {"issue_key": key, "url": f"{base_url}/browse/{key}"}
        except Exception:
            pass
        return None

    async def send_finding(self, config: dict, finding: dict) -> bool:
        result = await self.create_issue(config, finding)
        if result:
            self.log_event("jira", finding.get("target_id"),
                           f"Jira issue created: {result['issue_key']}",
                           f"Issue created for {finding.get('value', 'unknown')}: {result['url']}")
            return True
        return False
