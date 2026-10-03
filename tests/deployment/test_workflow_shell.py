"""Parse shell steps without running them or interpolating any real secrets."""
from pathlib import Path
import re
import subprocess
import textwrap
import unittest


class WorkflowShellTests(unittest.TestCase):
    def test_build_deploy_shell_steps_parse(self):
        workflow = Path(__file__).resolve().parents[2] / ".github/workflows/build-and-sign.yml"
        lines = workflow.read_text().splitlines()
        checked = 0
        for index, line in enumerate(lines):
            match = re.match(r"^( +)run: \|\s*$", line)
            if not match:
                continue
            indent = len(match.group(1))
            block = []
            for following in lines[index + 1:]:
                if following.strip() and len(following) - len(following.lstrip()) <= indent:
                    break
                block.append(following)
            script = re.sub(r"\$\{\{.*?\}\}", "test-value", textwrap.dedent("\n".join(block)))
            result = subprocess.run(["bash", "-n"], input=script, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, f"run block at line {index + 1}: {result.stderr}")
            checked += 1
        self.assertGreater(checked, 10)
