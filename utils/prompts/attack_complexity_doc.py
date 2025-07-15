from .templates import COMMON_TAIL

DOC_ATTACK_EVASION_QUERY: str = """
Analyze the document to detect attack evasion techniques following these strict criteria:

**Attack Evasion Criteria** (Must meet at least ONE):
1. Explicit mentions of anti-analysis methods (debugger detection/sandbox evasion)
2. Documented requirements for payload obfuscation/encryption
3. Recommended environment manipulation (memory randomization bypass)
4. Suggested timing-based anti-scanning mechanisms
5. Attacker-initiated configuration changes to bypass defenses (e.g., disabling firewalls)

**Analysis Workflow**:
1. Identify exploitation steps described in the document
2. Check if any step requires or implies evasion techniques (Criteria 1-5)
3. Specify exact document sections/pages/lines numbers supporting the judgment
4. After that, give your confidence score to describe your confidence level about your judgement
""" + COMMON_TAIL
    
DOC_INFO_DEPENDENCY_QUERY: str = """
Analyze the document to assess exploitation's information dependency:

**Dependency Criteria** (Must meet at least ONE):
1. Explicit requirement for target credentials
2. Documented need for environment-specific data
3. Configuration-dependent exploitation paths
4. Network topology dependency descriptions

**Analysis Workflow**:
1. Identify exploitation prerequisites in documentation
2. Check if target-specific info is required for success
3. Highlight relevant document sections/pages/lines
4. After that, give your confidence score to describe your confidence level about your judgement
""" + COMMON_TAIL

DOC_ATTACK_CONDITION_QUERY: str = """
Analyze the document to assess uncontrollable exploitation conditions:

**Uncontrollable Condition Criteria** (True if ANY met):
1. Dependency on pre-existing system configurations (e.g., "requires Java 6 runtime")
2. Dependency on unmanaged external services
3. Assumption of particular system states
4. Need for privileged network positioning

**Analysis Workflow**:
1. Identify described exploitation prerequisites
2. Evaluate if conditions require attacker-independent factors
3. Cite document sections/pages/lines as the evidence of criteria 1-4
4. After that, give your confidence score to describe your confidence level about your judgement
""" + COMMON_TAIL
    
DOC_ATTACK_PROBABILITY_QUERY: str = """
Analyze the document to assess probabilistic exploitation following these strict criteria:

**Probabilistic Indicators** (Must meet at least ONE):
1. Explicit success rate declarations (e.g., "1/10 attempts")
2. Time window dependency descriptions
3. Recommended retry mechanisms
4. Statistical prerequisite requirements

**Analysis Workflow**:
1. Extract exploitation process descriptions
2. Detect probability-dependent success conditions
3. Correlate findings (specific sections/pages/lines) with indicators 1-4
4. After that, give your confidence score to describe your confidence level about your judgement
""" + COMMON_TAIL 
    
DOC_PRIVILEGE_REQUIRED_QUERY: str = """
Analyze the document to assess privilege dependencies:

**Privilege Indicators** (True if ANY met):
1. Explicit privilege requirements (e.g., "requires root")
2. Documented privilege escalation steps
3. Dependency on administrator configurations
4. Minimum privilege level specifications

**Analysis Workflow**:
1. Identify privilege-related descriptions
2. Check if exploitation presumes access levels
3. Correlate with indicators 1-4
4. After that, give your confidence score to describe your confidence level about your judgement
""" + COMMON_TAIL
    
DOC_USER_INTERACTION_QUERY: str = """
Analyze the document to assess victim interaction needs:

**Interaction Indicators** (True if ANY met):
1. Explicit user action requirements (e.g., "requires victim to click")
2. Social engineering steps described
3. Manual triggering instructions
4. User-dependent configuration needs (e.g., "requires Outlook macro enabled")

**Analysis Workflow**:
1. Extract exploitation workflow descriptions
2. Detect mandatory user-side operations
3. Classify findings using indicators 1-4
4. After that, give your confidence score to describe your confidence level about your judgement
""" + COMMON_TAIL
    