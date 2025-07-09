from .templates import COMMON_TAIL

CODE_VUL_CODE_EXECUTION_QUERY: str = """
Analyze the codebase to detect arbitrary code execution vulnerabilities following these strict criteria:

**Arbitrary Code Execution Definition** (Must meet at least ONE):
1. Unsafe execution of system commands (e.g., use of eval/system/exec functions)
2. Deserialization of untrusted data without validation
3. Dynamic code loading from user-controlled sources
4. Path traversal leading to malicious code execution
5. Insecure reflection mechanisms
6. Memory corruption vulnerabilities (buffer overflow/use-after-free)

**Analysis Workflow** (You need to think step by step):
1. Locate code segments with file paths and line numbers that match defined patterns
2. Verify if the code allows control of executable content/parameters
3. Check for absence of input sanitization/context validation
4. Confirm the attack vector is reachable from untrusted inputs
5. For positive cases, specify the exact vulnerable code pattern
6. Finally, score your confidence based on code context clarity
""" + COMMON_TAIL

CODE_VUL_PRIVILEGE_ESCALATION_QUERY: str = """
Analyze the codebase to detect privilege escalation techniques following these strict criteria:

**Privilege Escalation Definition** (Must meet at least ONE):
1. Abusing setuid/setgid binaries with insecure permissions (e.g., world-writable)
2. Exploitable sudoers configuration (NOPASSWD rules for dangerous commands)
3. Kernel-space vulnerability exploitation patterns (e.g., dirty cow-like operations)
4. Improper access control modification (chmod/chown with insecure arguments)
5. Process injection techniques for privilege context switching
6. Scheduled task/service creation with elevated privileges (cron/systemd units)

**Analysis Workflow** (You need to think step by step):
1. Identify privilege context switching operations with file paths and line numbers
2. Verify if the implementation matches known escalation patterns
3. Check for explicit privilege manipulation (e.g., setuid(0), CAP_SYS_ADMIN usage)
4. Validate the persistence mechanism (if present)
5. Confirm the attack vector feasibility (requires->exploits relationship)
6. After that, give your confidence score based on code evidence clarity
""" + COMMON_TAIL

CODE_VUL_INFORMATION_LEAK_QUERY:str="""
Analyze the codebase to detect information leak execution following these strict criteria:

**Information Leak Definition** (Must meet at least ONE):
1. Sending sensitive data (e.g., passwords, tokens, personal information) to external servers or logs without proper encryption
2. Exposing internal system details (e.g., stack traces, configuration files) in error messages or responses to external users
3. Storing sensitive information in insecure locations (e.g., local files with weak permissions, unencrypted databases)
4. Transmitting data over unsecured communication channels (e.g., plain HTTP instead of HTTPS)
5. Including hard-coded sensitive information (e.g., credentials, API keys) in the codebase that could be exposed

**Analysis Workflow** (You need to think step by step):
1. Identify code segments handling sensitive data with file paths and line numbers
2. Verify matches with the defined information leak techniques above
3. If matched, describe specific implementation details
4. After that, give your confidence score to describe your confidence level about your judgement
""" + COMMON_TAIL

CODE_VUL_BYPASS_QUERY: str = """
Analyze the attack code to determine whether it leads to authentication bypass following these strict criteria:

**Authentication Bypass Definition** (Must meet all conditions below):
1. Exploits weak/forged authentication mechanisms (e.g., hardcoded credentials, bypassed authentication checks)
2. Manipulates session management (e.g., stolen session tokens, forged cookies)
3. Exploits authorization flaws (e.g., privilege escalation through role manipulation)
4. Bypasses multi-factor authentication (MFA) requirements
5. Exploits insecure direct object references (IDOR)
6. Uses credential stuffing or brute-force techniques against authentication endpoints

**Analysis Workflow** (You need to think step by step):
1. Identify code segments that interact with authentication mechanisms with file paths and line numbers
2. Verify matches with the defined authentication bypass techniques above
3. If matched, describe specific implementation details of the bypass technique
4. After that, give your confidence score to describe your confidence level about your judgement
5. Finally, provide a clear True/False conclusion about whether authentication bypass is achieved
""" + COMMON_TAIL

CODE_VUL_DENIAL_OF_SERVICE_QUERY: str = """
Analyze the codebase to detect denial of service attack patterns following these strict criteria:

**Denial of Service Definition** (Must meet at least ONE):
1. Unbounded resource consumption (e.g., infinite loops, uncontrolled memory allocation)
2. Intentional system crash or abnormal termination triggers
3. Resource exhaustion techniques (e.g file., handle exhaustion, database connection flooding)
4. Network flooding mechanisms (e.g., excessive request generation, bandwidth saturation)

**Analysis Workflow** (You need to think step by step):
1. Identify code segments that may cause resource exhaustion or system instability with file paths and line numbers
2. Verify matches with the defined denial of service techniques above
3. If matched, describe specific implementation details including:
   - How the resource consumption grows
   - Under what conditions the DoS condition is triggered
   - Potential impact on system availability
4. After that, give your confidence score to describe your confidence level about your judgement
""" + COMMON_TAIL