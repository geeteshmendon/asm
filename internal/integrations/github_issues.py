import httpx
from internal.integrations.base import Integration


class GitHubIssuesIntegration(Integration):
    name = "github_issues"

    async def create_issue(self, config: dict, finding: dict) -> dict | None:
        try:
            repo = config["repo"].strip("/")
            token = config["token"]

            severity = finding.get("severity", "medium")
            labels = [severity, "asm", finding.get("type", "finding")]

            issue_data = {
                "title": finding.get("title", "ASM Finding"),
                "body": f"## ASM Finding\n\n"
                        f"**Type:** {finding.get('type', 'N/A')}\n"
                        f"**Asset:** {finding.get('value', 'N/A')}\n"
                        f"**Severity:** {severity}\n\n"
                        f"**Details:**\n{finding.get('details', 'N/A')}",
                "labels": labels,
            }

            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(
                    f"https://api.github.com/repos/{repo}/issues",
                    json=issue_data,
                    headers={
                        "Authorization": f"token {token}",
                        "Accept": "application/vnd.github.v3+json",
                    },
                )
                if resp.status_code in (200, 201):
                    data = resp.json()
                    return {"issue_number": data.get("number"), "url": data.get("html_url")}
        except Exception:
            pass
        return None

    async def send_finding(self, config: dict, finding: dict) -> bool:
        result = await self.create_issue(config, finding)
        if result:
            self.log_event("github_issues", finding.get("target_id"),
                           f"GitHub issue created: #{result['issue_number']}",
                           f"Issue created for {finding.get('value', 'unknown')}: {result['url']}")
            return True
        return False
