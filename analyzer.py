import ast
import re


def analyze_code(code):

    quality_issues = []
    security_issues = []

    # Empty code check
    if not code.strip():
        return {
            "quality_score": 0,
            "security_score": 0,
            "issues": ["No code provided"],
            "security_issues": ["No code provided"]
        }

    lines = code.splitlines()

    # ==================================================
    # 1. SYNTAX ANALYSIS
    # ==================================================

    try:
        tree = ast.parse(code)

    except SyntaxError as e:

        quality_issues.append(
            f"Syntax Error on line {e.lineno}: {e.msg}"
        )

        return {
            "quality_score": 20,
            "security_score": 100,
            "issues": quality_issues,
            "security_issues": []
        }

    # ==================================================
    # 2. CODE QUALITY ANALYSIS
    # ==================================================

    # Long lines
    for line_number, line in enumerate(lines, start=1):

        if len(line) > 100:

            quality_issues.append(
                f"Line {line_number}: Line is too long."
            )

    # Too many lines
    if len(lines) > 50:

        quality_issues.append(
            "Code is too long. Break it into smaller functions."
        )

    # TODO comments
    if re.search(r"\bTODO\b", code, re.IGNORECASE):

        quality_issues.append(
            "TODO found. Some work may be unfinished."
        )

    # print() usage
    if re.search(r"\bprint\s*\(", code):

        quality_issues.append(
            "print() detected. Consider using logging in production code."
        )

    # Bare except
    if re.search(r"except\s*:", code):

        quality_issues.append(
            "Bare 'except:' detected. Catch specific exceptions."
        )

    # == None
    if re.search(r"==\s*None", code):

        quality_issues.append(
            "Use 'is None' instead of '== None'."
        )

    # != None
    if re.search(r"!=\s*None", code):

        quality_issues.append(
            "Use 'is not None' instead of '!= None'."
        )

    # ==================================================
    # 3. FUNCTION QUALITY
    # ==================================================

    functions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]

    for function in functions:

        # Very long function
        if len(function.body) > 15:

            quality_issues.append(
                f"Function '{function.name}' is too long. "
                f"Consider splitting it into smaller functions."
            )

        # No parameters
        if len(function.args.args) == 0:

            quality_issues.append(
                f"Function '{function.name}' has no parameters."
            )

    # ==================================================
    # 4. UNUSED VARIABLES
    # ==================================================

    assignments = []

    for node in ast.walk(tree):

        if isinstance(node, ast.Assign):

            for target in node.targets:

                if isinstance(target, ast.Name):

                    assignments.append(target.id)

    for variable in assignments:

        # Ignore common variables
        if variable not in ["_", "i", "j"]:

            pattern = rf"\b{re.escape(variable)}\b"

            occurrences = len(
                re.findall(pattern, code)
            )

            if occurrences == 1:

                quality_issues.append(
                    f"Variable '{variable}' may be unused."
                )

    # ==================================================
    # 5. SECURITY ANALYSIS
    # ==================================================

    # eval()
    if re.search(r"\beval\s*\(", code):

        security_issues.append(
            "CRITICAL: eval() detected. "
            "It can execute untrusted input."
        )

    # exec()
    if re.search(r"\bexec\s*\(", code):

        security_issues.append(
            "CRITICAL: exec() detected. "
            "Avoid executing dynamic code."
        )

    # Hardcoded password
    if re.search(
        r"(password|passwd|pwd)\s*=\s*['\"]",
        code,
        re.IGNORECASE
    ):

        security_issues.append(
            "HIGH: Hardcoded password detected. "
            "Use environment variables."
        )

    # API key
    if re.search(
        r"(api_key|apikey|secret_key)\s*=\s*['\"]",
        code,
        re.IGNORECASE
    ):

        security_issues.append(
            "HIGH: Possible hardcoded API key detected."
        )

    # SQL Injection
    if (
        "SELECT" in code.upper()
        and ("+" in code or "%" in code)
    ):

        security_issues.append(
            "HIGH: Possible SQL injection risk. "
            "Use parameterized queries."
        )

    # os.system()
    if re.search(r"os\.system\s*\(", code):

        security_issues.append(
            "HIGH: os.system() detected. "
            "Avoid executing untrusted system commands."
        )

    # subprocess shell=True
    if re.search(r"shell\s*=\s*True", code):

        security_issues.append(
            "HIGH: shell=True detected. "
            "This may allow command injection."
        )

    # pickle
    if re.search(r"pickle\.load\s*\(", code):

        security_issues.append(
            "HIGH: Unsafe pickle.load() detected."
        )

    # ==================================================
    # 6. SCORE CALCULATION
    # ==================================================

    quality_score = max(
        0,
        100 - (len(quality_issues) * 10)
    )

    security_score = max(
        0,
        100 - (len(security_issues) * 20)
    )

    # ==================================================
    # 7. RESULT
    # ==================================================

    return {
        "quality_score": quality_score,
        "security_score": security_score,
        "issues": quality_issues,
        "security_issues": security_issues
    }