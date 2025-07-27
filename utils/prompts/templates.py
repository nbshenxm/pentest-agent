BASIC_CONSTRAINTS: str = """
**Constraints**:
- Ignore non-readable files (images/binaries)
- The analysis should be strictly defined against the standard to avoid confusing the attack logic with the characteristics of the code implementation
- Final conclusion must use <True|False> format
- Confidence score must be integer 1-5, smaller numbers indicate that you are not certain about the judgement or you need more information to confirm
"""

BASIC_RESPONSE_FORMAT: str = """
**Response Format**:
[File Analysis]
1. path/to/file:line_number - Technique detected (Technique ID number)
- Implementation details...

[Conclusion]
<True|False>

[Confidence]
4
"""

COMMON_TAIL: str = BASIC_CONSTRAINTS + BASIC_RESPONSE_FORMAT

BASE_JUDGE_QUERY_1: str = """
Perform a final judgment analysis based on multiple security assistants' assessments:

**Adjudication Protocol**
1. Critical Evidence Check:
   - Identify concrete technical evidence in each analysis.
   - Prioritize findings with code/docs references
2. Conflict Resolution:
   - Technical specificity > General statements
   - Code references > Document analysis
   - Recent CVE patterns > Historical data

**Voter Submissions**""" # please do not break the quotes to a new line, as it will cause an additional line break in the query, resulting in formatting issues

BASE_JUDGE_QUERY_2: str = """
**Judgment Process**
1. Evidence Correlation: Map technical proofs across voters.
2. Final Determination: 
   - Must have a final yes or no conclusion is based on the views of all voters
   - You can disagree with all of assistants
   - Flag irreconcilable conflicts for human review

**Constraints**:
- Ignore non-readable files (images/binaries)
- Final conclusion must use <True|False> format
- Do not use explanatory notes

**Output Format**
[Consensus Analysis] 
- Agreed points: (List at least two key pieces of evidence endorsed by voters)
- Disputed points: (Divergent dimensions of analysis)

[Final Judgment]
<True> or <False>
"""

ENHANCED_CONSTRAINTS = BASIC_CONSTRAINTS + """
**Domain-Specific Constraints**:
- When the code snippet is incomplete, the confidence must be lowered (Confidence ≤ 3)
- The judgment on compiled languages requires the identification of build configuration files (Makefile/pom.xml, etc.)
- It is essential to distinguish between test code and actual attack code
"""

EXECUTION_RESPONSE_FORMAT: str = """
**Response Format**:
[Execution Chain]
1. src/upload.py:32 - File parser initialization 
   - Accepts unsanitized ZIP files
2. lib/decoder.c:87 - Buffer overflow in parse_header() 
   - Overwrites return address
3. payload.bin - Embedded shellcode execution 
   - Spawns reverse shell on 192.168.1.100:4444

[Final Effect]
Remote code execution via malicious archive upload

[Confidence] 
4
"""