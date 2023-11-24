import hashlib
import json
from dojo.models import Finding

class DetectSecretsParser(object):
    """
    A class that can be used to parse the detect-secrets JSON report file
    """

    def get_scan_types(self):
        return ["Detect-secrets Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Detect-secrets Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import JSON output for detect-secrets scan report."

    def get_findings(self, filename, test):
        try:
            file_contents = filename.read().decode('utf-8')
            issues = json.loads(file_contents)
        except Exception as e:
            raise ValueError(f"Failed to parse JSON: {str(e)}")

        findings = []

        for file_path, file_issues in issues.items():
            for issue in file_issues:
                line = issue["line"]
                string = issue["string"]
                line_number = issue["line_number"]
                rule = issue["rule"]
                reason = issue["reason"]
                fingerprint = issue["fingerprint"]

                title = f"Hard Coded {rule} found in {file_path}"
                description = f"**Reason:** {reason}\n"
                description += f"**String Found:**\n\n```\n{line}\n```\n"
                description += f"**Line:** {line_number}\n"
                description += f"**Fingerprint:** {fingerprint}"

                severity = "Critical"

                finding = Finding(
                    title=title,
                    test=test,
                    cwe=798,
                    description=description,
                    severity=severity,
                    file_path=file_path,
                    line=line_number,
                    dynamic_finding=False,
                    static_finding=True,
                )
                findings.append(finding)

        return findings
