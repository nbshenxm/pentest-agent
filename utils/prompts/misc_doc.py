from .templates import COMMON_TAIL

DOC_VUL_CODE_EXECUTION_QUERY = """
Based on the available information, please determine if the vulnerability allows arbitrary code execution by meeting AT LEAST TWO criteria:

**Execution Criteria** (Must meet ≥2):
1. Documented ability to execute OS commands/scripts
2. Existence of injection points (eval/deserialization)
3. Clear exploit chain described (input -> execution path)
4. Evidence of memory corruption primitives
5. Environment allows execution without sandboxing

**Analysis Workflow**:
1. Identify potential execution vectors in documentation
2. Verify if ≥2 criteria are explicitly/implicitly met
3. Check for environmental constraints affecting exploitability
4. Reference exact document locations (pages/lines)
5. Assign confidence based on evidence clarity
""" + COMMON_TAIL

DOC_VUL_PRIVILEGE_ESCALATION_QUERY = """
Based on the available information, please determine if the vulnerability enables privilege escalation by meeting AT LEAST ONE criteria:

**Escalation Criteria**:
1. Documented permission bypass mechanisms
2. Privilege inheritance flaws described
3. Improper sandbox escaping methods
4. Ability to modify security tokens/credentials
5. Default configurations with excessive privileges

**Analysis Workflow**:
1. Map documented access control flows
2. Identify privilege boundary violations
3. Verify exploit prerequisites (e.g., required access level)
4. Reference exact document locations (pages/lines)
5. Consider platform-specific security mechanisms
""" + COMMON_TAIL

DOC_VUL_INFORMATION_LEAK_QUERY = """
Based on the available information, please determine if the vulnerability causes information leak by meeting AT LEAST ONE criteria:

**Leakage Criteria**:
1. Unintended data exposure channels described
2. Missing access controls on sensitive resources
3. Debugging interfaces left enabled in production
4. Error messages revealing sensitive data
5. Cryptographic weaknesses documented

**Analysis Workflow**:
1. Identify sensitive data handling processes
2. Check for insufficient validation/sanitization
3. Verify data flow paths to untrusted interfaces
4. Reference exact document locations (pages/lines)
5. Consider data classification levels
""" + COMMON_TAIL

DOC_VUL_BYPASS_QUERY = """
Based on the available information, please determine if the vulnerability allows authentication bypass by meeting AT LEAST ONE criteria:

**Bypass Criteria**:
1. Documented flaws in auth protocols
2. Hardcoded credentials/backdoor accounts
3. Weak session management mechanisms
4. Ability to modify auth tokens/signatures
5. Missing MFA enforcement

**Analysis Workflow**:
1. Analyze authentication workflow documentation
2. Identify missing validation steps
3. Check for cryptographic implementation flaws
4. Reference exact document locations (pages/lines)
5. Consider attack surface (remote/local access)
""" + COMMON_TAIL

DOC_VUL_DENIAL_OF_SERVICE_QUERY = """
Based on the available information, please determine if the vulnerability causes denial of service by meeting AT LEAST ONE criteria:

**DoS Criteria**:
1. Documented resource exhaustion vectors
2. Unhandled exceptional conditions
3. Service state corruption mechanisms
4. Amplification attack possibilities
5. Lack of rate limiting controls

**Analysis Workflow**:
1. Identify critical resource management processes
2. Check failure recovery mechanisms
3. Analyze attack complexity requirements
4. Reference exact document locations (pages/lines)
5. Consider service architecture (distributed/etc)
""" + COMMON_TAIL

DIRECT_JUDGE_DOC: str = """
You are a cybersecurity expert evaluating exploit documents. Based on the analysis of the doc, provide a concise assessment and a final score between 0-50.

Consider these key factors:

1. **Vulnerability Type** (in order of severity):
   - Code Execution (highest impact)
   - Privilege Escalation 
   - Denial of Service
   - Information Leak
   - Bypass
   - Unknown (lowest impact)

2. **Exploit Maturity**:
   - Exploit (fully functional weaponized code)
   - PoC (proof-of-concept demonstrating vulnerability)
   - None/Unknown (limited or no practical value)

3. **Attack Characteristics**:
   - Remote vs Local exploitation potential
   - Attack complexity features (evasion techniques, dependencies, conditions, probability, privilege requirements, user interaction)

**Scoring Guidelines:**
- 45-50: Weaponized remote code execution exploits with low complexity
- 40-44: Reliable remote exploits or sophisticated local privilege escalations  
- 35-39: Functional PoCs with practical attack vectors
- 30-34: Limited PoCs or complex attack requirements
- 25-29: Basic vulnerability demonstrations
- Below 25: Theoretical or non-practical exploits

**Output Format:**
Provide a brief analysis (2-3 sentences) followed by the score in this exact format:
[score]
X

Where X is your numerical rating (0-50).
"""