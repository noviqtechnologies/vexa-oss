"""
Bandit Scanner for Python Security Analysis.

SS-001: Bandit - Python security issues with CWE mapping
Modes: LOCAL, CONTAINER
"""

import json
from pathlib import Path
from typing import List, Optional

from vexa.scanners.base import (
    BaseScanner,
    Finding,
    FindingSeverity,
    ScanMode,
)
from vexa.common.logging import get_logger


logger = get_logger(__name__)


class BanditScanner(BaseScanner):
    """
    Bandit scanner for Python security analysis.

    Bandit is a tool designed to find common security issues in Python code.
    It produces JSON output with severity and confidence ratings.
    """

    name = "bandit"
    executable = "bandit"
    supported_modes = [ScanMode.LOCAL, ScanMode.CONTAINER]

    def get_command(
        self, path: Path, exclusions: Optional[List[str]] = None
    ) -> List[str]:
        """Build Bandit command."""

        cmd = [
            "bandit",
            "-r",  # Recursive
            str(path),
            "-f",
            "json",  # JSON output
            "--quiet",  # Quiet mode
        ]

        if exclusions:
            cmd.extend(["-x", ",".join(exclusions)])

        return cmd

    def parse_output(self, output: str, target_path: Path) -> List[Finding]:
        """Parse Bandit JSON output into normalized findings."""
        findings = []

        if not output.strip():
            return findings

        try:
            data = json.loads(output)
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse Bandit JSON output: %s", e)
            return findings

        results = data.get("results", [])

        for result in results:
            raw_code = result.get("code", "")
            lines = raw_code.splitlines()

            line_nums = []
            cleaned_lines = []
            import re

            for line in lines:
                # Bandit prepends "123  " to lines. Match: [optional space] [digits] [space(s)] [content]
                match = re.search(r"^\s*(\d+)\s+(.*)", line)
                if match:
                    line_nums.append(int(match.group(1)))
                    cleaned_lines.append(match.group(2))
                else:
                    # Fallback for unexpected format
                    cleaned_lines.append(line)

            # Determine range. If we couldn't parse line numbers, fallback to the single line reported.
            if line_nums:
                f_line_start = min(line_nums)
                f_line_end = max(line_nums)
            else:
                f_line_start = result.get("line_number", 0)
                f_line_end = f_line_start

            finding = Finding(
                id=self._generate_finding_id(
                    self.name,
                    result.get("filename", "").replace("\\", "/"),
                    result.get("line_number", 0),
                    result.get("test_id", ""),
                ),
                scanner=self.name,
                title=result.get("test_name", "Unknown Issue"),
                description=result.get("issue_text", ""),
                severity=self._map_severity(result.get("issue_severity", "MEDIUM")),
                file_path=result.get("filename", "").replace("\\", "/"),
                line_start=f_line_start,
                line_end=f_line_end,
                code_snippet="\n".join(cleaned_lines),
                confidence=result.get("issue_confidence", "MEDIUM").lower(),
                cwe_ids=self._extract_cwe(result),
                raw_data=result,
            )
            findings.append(finding)

        return findings

    def _map_severity(self, severity: str) -> FindingSeverity:
        """Map Bandit severity to normalized severity."""
        mapping = {
            "HIGH": FindingSeverity.HIGH,
            "MEDIUM": FindingSeverity.MEDIUM,
            "LOW": FindingSeverity.LOW,
        }
        return mapping.get(severity.upper(), FindingSeverity.MEDIUM)

    def _extract_cwe(self, result: dict) -> List[str]:
        """Extract CWE IDs from Bandit result."""
        cwe_ids = []

        # Bandit may include CWE in issue_cwe field
        if "issue_cwe" in result:
            cwe = result["issue_cwe"]
            if isinstance(cwe, dict) and "id" in cwe:
                cwe_ids.append(f"CWE-{cwe['id']}")
            elif isinstance(cwe, (int, str)):
                cwe_ids.append(f"CWE-{cwe}")

        # Also check test_id mappings
        test_id = result.get("test_id", "")
        cwe_mapping = {
            "B101": ["CWE-703"],  # assert_used
            "B102": ["CWE-78"],  # exec_used
            "B103": ["CWE-732"],  # set_bad_file_permissions
            "B104": ["CWE-200"],  # hardcoded_bind_all_interfaces
            "B105": ["CWE-259"],  # hardcoded_password_string
            "B106": ["CWE-259"],  # hardcoded_password_funcarg
            "B107": ["CWE-259"],  # hardcoded_password_default
            "B108": ["CWE-377"],  # hardcoded_tmp_directory
            "B110": ["CWE-89"],  # try_except_pass
            "B201": ["CWE-94"],  # flask_debug_true
            "B301": ["CWE-502"],  # pickle
            "B303": ["CWE-327"],  # md5
            "B304": ["CWE-327"],  # des
            "B305": ["CWE-327"],  # cipher
            "B306": ["CWE-330"],  # mktemp_q
            "B307": ["CWE-78"],  # eval
            "B308": ["CWE-79"],  # mark_safe
            "B310": ["CWE-22"],  # urllib_urlopen
            "B311": ["CWE-330"],  # random
            "B312": ["CWE-295"],  # telnetlib
            "B313": ["CWE-611"],  # xml_bad_cElementTree
            "B320": ["CWE-611"],  # xml_bad_sax
            "B321": ["CWE-89"],  # ftplib
            "B323": ["CWE-295"],  # unverified_context
            "B324": ["CWE-327"],  # hashlib_insecure
            "B501": ["CWE-295"],  # request_with_no_cert_validation
            "B502": ["CWE-295"],  # ssl_with_bad_version
            "B503": ["CWE-295"],  # ssl_with_bad_defaults
            "B504": ["CWE-295"],  # ssl_with_no_version
            "B505": ["CWE-295"],  # weak_cryptographic_key
            "B506": ["CWE-327"],  # yaml_load
            "B507": ["CWE-295"],  # ssh_no_host_key_verification
            "B601": ["CWE-78"],  # paramiko_calls
            "B602": ["CWE-78"],  # subprocess_popen_with_shell
            "B603": ["CWE-78"],  # subprocess_without_shell
            "B604": ["CWE-78"],  # any_other_function_with_shell
            "B605": ["CWE-78"],  # start_process_with_a_shell
            "B606": ["CWE-78"],  # start_process_with_no_shell
            "B607": ["CWE-78"],  # start_process_with_partial_path
            "B608": ["CWE-89"],  # hardcoded_sql_expressions
            "B609": ["CWE-78"],  # linux_commands_wildcard_injection
            "B610": ["CWE-94"],  # django_extra_used
            "B611": ["CWE-94"],  # django_rawsql_used
            "B701": ["CWE-94"],  # jinja2_autoescape_false
            "B702": ["CWE-79"],  # use_of_mako_templates
            "B703": ["CWE-79"],  # django_mark_safe
        }

        if test_id in cwe_mapping:
            for cwe in cwe_mapping[test_id]:
                if cwe not in cwe_ids:
                    cwe_ids.append(cwe)

        return cwe_ids
