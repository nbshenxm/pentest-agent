from .templates import COMMON_TAIL

CODE_ISREMOTE_QUERY: str = """
Analyze the codebase to determine remote exploitability following these strict criteria:

**Remote Exploit Definition** (Must meet ALL):
1. Exposes network interface/API (HTTP/RPC/Socket etc.)
2. Does NOT require physical/local console access
3. Attack vector transmission via network protocols
4. No mandatory pre-auth on critical paths

**Analysis Workflow**:
1. Identify network entry points with file paths and line numbers
2. Verify authentication mechanisms in critical paths
3. Check payload transmission channel implementation
4. Validate absence of physical access requirements
""" + COMMON_TAIL

DOC_ISREMOTE_QUERY: str = """
Analyze vulnerability documentation to determine remote exploitability with these criteria:

**Remote Exploit Indicators** (Must meet ANY):
1. Explicit "Remote" classification in CVE/CWE 
2. Attack vector contains "Network" 
3. Authentication not required for initial access
4. Documented exploitation through standard protocols

**Analysis Workflow**:
1. Extract vulnerability type from CWE/CVE metadata 
2. Parse attack vector descriptions 
3. Check privilege requirements 
4. Verify protocol specifications
""" + COMMON_TAIL