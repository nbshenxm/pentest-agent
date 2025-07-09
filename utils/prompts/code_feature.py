from .templates import BASIC_CONSTRAINTS, ENHANCED_CONSTRAINTS, EXECUTION_RESPONSE_FORMAT

CODE_DESCRIPTION_QUERY: str = """
Based on the available information, analyze the exploit code execution flow following these guidelines:

**Execution Flow Definition** (Must cover):
1. Initial trigger condition (e.g. API call/file upload)
2. Critical vulnerability invocation point
3. Payload propagation path
4. Final effect (e.g. RCE/Data leak)

**Analysis Workflow**:
1. Identify entry points with file paths and line numbers
2. Trace data flow through vulnerable functions
3. Map control transitions between components
4. Verify end-to-end exploit feasibility
""" + BASIC_CONSTRAINTS + EXECUTION_RESPONSE_FORMAT
    
CODE_POC_QUERY: str = """
Based on the available information, please determine PoC validity through these checks:

**PoC Validity Indicators**:
1. Contains reproducible test cases
2. Has vulnerability assertion logic
3. Produces deterministic output
4. Includes environment setup instructions

**Analysis Workflow**:
1. Scan for unit test frameworks (pytest/JUnit)
2. Check assert/verify statements 
3. Validate result checking mechanisms
""" + ENHANCED_CONSTRAINTS + """
**Response Format**:
[PoC Evidence]
1. tests/exploit_test.py:32 - assert shell.open() returns 0
2. Dockerfile - Pre-configured vulnerable environment

[Conclusion]
<True|False>

[Confidence]
4
"""

CODE_FLEXIBILITY_QUERY: str = """
Based on the available information, please evaluate attack customization capability:

**Flexibility Factors**:
1. Parameterized input vectors
2. Configurable payload modules
3. Modular architecture design
4. Exposed API endpoints

**Analysis Workflow**:
1. Identify configuration files (config.yaml)
2. Check CLI argument parsing 
3. Scan for plugin interfaces
""" + ENHANCED_CONSTRAINTS + """
**Response Format**:
[Customization Points]
1. config/attack_params.json - Payload size/timeout
2. src/payload_gen.py - Modular generator class

[Limitations]
Hardcoded target IP in core.py:89

[Conclusion]
<True|False>

[Confidence]
4
"""
CODE_FUNCTIONALITY_QUERY: str = """
Based on the available information, please assess attack goal achievability:

**Functionality Checklist**:
1. Bypasses security controls
2. Establishes unauthorized access
3. Achieves CWE/CVE documented impact
4. Leaves detectable forensic traces

**Analysis Workflow**:
1. Compare with MITRE ATT&CK TTPs
2. Check privilege escalation paths
3. Verify persistence mechanisms
""" + ENHANCED_CONSTRAINTS + """
**Response Format**:
[Attack Capabilities]
1. memdump.py - Extracts credentials from LSASS
2. Exploits CVE-2021-34527 (PrintNightmare)

[Missing Features]
No lateral movement modules

[Conclusion]
<True|False>

[Confidence]
5
"""

CODE_RELAVANCE_QUERY: str = """Please verify whether the code execution can verify the existence of the vulnerability impact: \n
                                    vulnerability description: vul_description \n
                                    code execution description: code_description \n
                                    Answer with "True" or "False"."""

CODE_AVAILABILITY_QUERY: str = """Based on the available information, please determine whether the source code files are available. Source code files should contain code written in human understandable PROGRAMMING languages and the specific file usually with .py/.java/.go etc. Note that you can ignore image, binary and other files that are not human readable.
                                    Answer with "True" or "False"."""

    

CODE_AUTOMATION_QUERY: str = """Based on the available information, please determine whether the code execution can be automated (i.e., it does not require manual setup or human interaction). Note that you can ignore image, binary and other files that are not human readable.
                                    Answer with "True" or "False"."""
