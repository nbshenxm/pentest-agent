from .templates import COMMON_TAIL

CODE_ATTACK_EVASION_QUERY: str = """
Analyze the codebase to detect attack evasion techniques following these strict criteria:

**Attack Evasion Definition** (Must meet at least ONE):
1. Presence of anti-debugging techniques (e.g., IsDebuggerPresent calls)
2. Environment detection (VM/sandbox checks)
3. Code obfuscation/encryption of core logic
4. Time delays to bypass automated analysis
5. Process memory manipulation to evade scanning
6. Network covert technology (e.g., traffic encryption, DGA domain name generation algorithm)

**Analysis Workflow** (You need to think step by step):
1. Identify suspicious code segments with file paths and line numbers
2. Verify matches with the defined evasion techniques above
3. If matched, describe specific implementation details
4. After that, give your confidence score to describe your confidence level about your judgement
""" + COMMON_TAIL

CODE_INFO_DEPENDENCY_QUERY: str = """
Analyze the codebase to detect target exploitation information dependencies following these strict criteria:

**Dependency Criteria** (Must meet at least ONE):
1. Hardcoded credentials (username/password in plaintext)
2. Dynamic credential acquisition (keychain access/credential managers)
3. Sensitive data and environment variable reliance (AWS_ACCESS_KEY_ID etc.)
4. External configuration parsing (database connection strings)
5. Hardware binding logic (e.g. reading device fingerprint/physical serial number)

**Analysis Workflow**:
1. Locate sensitive data handling in code (with file/line references)
2. Verify if data sourcing requires target-specific information
3. Classify dependency type according to criteria 1-5 and describe specific details
4. After that, give your confidence score to describe your confidence level about your judgement
""" + COMMON_TAIL
    
CODE_ATTACK_CONDITION_QUERY: str = """
Analyze the codebase to detect uncontrollable preconditions for execution:

**Uncontrollable Condition Criteria** (True if ANY met):
1. Hardcoded dependencies (specific IP/domain/path)
2. Third-party service API requirements
3. Privilege checks beyond default permissions (Focus on dependencies)
4. Environmental assumptions (registry keys/OS features)
5. Physical device dependencies (e.g. dedicated hardware drivers)

**Analysis Workflow**:
1. Locate environmental dependencies in code
2. Determine if dependency control exceeds attacker's capability
3. Map findings to criteria 1-5 with code references
4. After that, give your confidence score to describe your confidence level about your judgement
""" + COMMON_TAIL

CODE_ATTACK_PROBABILITY_QUERY: str = """
Analyze the codebase to detect probabilistic exploitation characteristics following these strict criteria:

**Probabilistic Execution Criteria** (Must meet at least ONE):
1. Race condition constructs (unprotected shared resources)
2. Time-sensitive operations without synchronization
3. Randomness-dependent execution paths (e.g., rand() branching)
4. Statistical collision mechanisms (hash/address guessing)
5. Physical entropy source dependence (e.g. temperature sensor/RDRAND directive)

**Analysis Workflow**:
1. Identify concurrency/randomness patterns in code
2. Verify if success requires probabilistic conditions
3. Map technical implementations to criteria 1-5 with code lines
4. After that, give your confidence score to describe your confidence level about your judgement
""" + COMMON_TAIL
                                        
    # Privileges Required: None, Low, High
CODE_PRIVILEGE_REQUIRED_QUERY: str = """
Analyze the codebase to detect privilege requirements for exploitation:

**Privilege Criteria** (True if ANY met):
1. Privileged API calls (e.g., SeDebugPrivilege)
2. Permission escalation attempts (setuid/sudo)
3. Protected resource access (system files/registry, focus only on how permissions are obtained)
4. Installation path dependencies (Program Files)

**Analysis Workflow**:
1. Locate privilege-sensitive operations in code
2. Verify if execution requires elevated rights
3. Classify findings using criteria 1-4
4. After that, give your confidence score to describe your confidence level about your judgement
""" + COMMON_TAIL
    
    # User Interaction: None, Required
CODE_USER_INTERACTION_QUERY: str = """
Analyze the codebase to detect third-party user interaction requirements:

**Interaction Criteria** (True if ANY met):
1. UI event handlers (click/input callbacks)
2. External trigger waiting loops (e.g., MessageBox)
3. File open dialog dependencies
4. User credential input flows

**Analysis Workflow**:
1. Identify user-triggered execution paths
2. Verify if attack requires victim-side actions
3. Map technical patterns to criteria 1-4
4. After that, give your confidence score to describe your confidence level about your judgement
""" + COMMON_TAIL
    