import json
import os
from packaging import version
from utils.model_manager import get_model
import logging
import yaml

logger = logging.getLogger(__name__)

config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'configs', 'config.yaml')
with open(config_path, 'r', encoding='utf-8') as f:
    config = yaml.safe_load(f)

def get_llm():
    planning_config = config['runtime']['planning']
    model_name = planning_config['model']
    return get_model(model_name)

VERSION_PROMPT = """You are a cybersecurity expert specializing in CVE analysis. Your task is to:
1. Analyze CVE descriptions to identify affected version ranges
2. Extract version information in standardized format:
   - Use semantic versioning (major.minor.patch) where possible
   - For open-ended ranges, use N/min or N/max
   - For single version vulnerabilities, set min=max
3. Return results in JSON format:
   [{"cve_id": "CVE-XXXX", "min_version": "x.y.z", "max_version": "x.y.z"}, {"cve_id": "CVE-XXXX", "min_version": "x.y.z", "max_version": "x.y.z"},...]

Guidelines:
- Pay special attention to phrases like:
  "before X", "through X", "up to X", "after X", "from X to Y"
- Ignore non-version related information
- For PHPMailer-style versions (6.4.1), maintain the same format
- If no version info found, use "N/min" and "N/max"
- Always return valid JSON, even if uncertain
"""

def extract_cve_info(cvemap_res):
    cve_lines = []
    for cve in cvemap_res:
        cve_id = cve.get("cve_id", "N/A")
        description = cve.get("cve_description", "No description available")
        cve_lines.append(f"{cve_id}: {description}")
    return "\n".join(cve_lines)

def extract_version_ranges(cve_text):
    """
    use LLMto extract version range from CVE txt
    return: [{"cve_id": <str>, "min_version": <str>, "max_version": <str>}]
    """
    llm = get_llm()
    prompt = VERSION_PROMPT + "\nCVE Descriptions:\n" + cve_text + "\nReturn only a valid JSON array as specified."
    # compatible for both langchain and llamaindex LLM
    try:
        from langchain_core.messages import HumanMessage
        response = llm.invoke([HumanMessage(content=prompt)])
    
    # extract text and try to parse as JSON
        response_text = response.content.strip() if hasattr(response, 'content') else str(response)
    except Exception as e:
        logger.error(f"LLM call failed: {e}")
        return []
    
    try:
        # try to extract JSON (may be included in ```json ``` tags)
        if "```json" in response_text:
            json_str = response_text.split("```json")[1].split("```", 1)[0].strip()
        else:
            json_str = response_text
        
        result = json.loads(json_str)
        if isinstance(result, dict):
            return [result]  # for single dict, transfer to list
        return result
    except json.JSONDecodeError:
        print(f"Failed to parse LLM response as JSON: {response_text}")
        return []  # return empty list for post process
    
def process_cve_versions(cvemap_res):
    # Step 1: Extract CVE text
    cve_text = extract_cve_info(cvemap_res)
    
    # Step 2: Extract version ranges
    version_ranges = extract_version_ranges(cve_text)
    
    # Step 3: Standardize output
    standardized = []
    for item in version_ranges:
        standardized.append({
            "cve_id": item.get("cve_id", "UNKNOWN"),
            "min_version": item.get("min_version", "N/min"),
            "max_version": item.get("max_version", "N/max")
        })
    
    return standardized

def is_version_affected(cve_entry, target_version):
    """
    Check if the target version is within the affected range of the CVE
    :param cve_entry: A single CVE entry, such as {'cve_id':..., 'min_version':..., 'max_version':...}
    :param target_version: The version number to check (str)
    :return: bool (whether affected)
    """
    try:
        target = version.parse(target_version)
        
        # Handle minimum version
        min_ver = cve_entry["min_version"]
        if min_ver not in ["N/min", ""]:
            if version.parse(min_ver) > target:
                return False
        
        # Handle maximum version
        max_ver = cve_entry["max_version"]
        if max_ver not in ["N/max", ""]:
            if version.parse(max_ver) < target:
                return False
        
        return True
    except:
        return False  # Return True conservatively if version parsing fails, or adjust as needed

def get_affected_cve(cvemap_res, target_version):
    cve_list = process_cve_versions(cvemap_res)
    affected_cves = [
        cve for cve in cve_list 
        if is_version_affected(cve, target_version)
    ]

    return affected_cves


# cve_list = [{'cve_id': 'CVE-2021-3603', 'min_version': 'N/min', 'max_version': '6.4.1'}, {'cve_id': 'CVE-2021-34551', 'min_version': 'N/min', 'max_version': '6.5.0'}, {'cve_id': 'CVE-2020-36326', 'min_version': '6.1.8', 'max_version': '6.4.0'}, {'cve_id': 'CVE-2020-13625', 'min_version': 'N/min', 'max_version': '6.1.6'}, {'cve_id': 'CVE-2018-19296', 'min_version': 'N/min', 'max_version': '5.2.27'}, {'cve_id': 'CVE-2018-19296', 'min_version': '6.0.0', 'max_version': '6.0.6'}, {'cve_id': 'CVE-2017-5223', 'min_version': 'N/min', 'max_version': '5.2.22'}, {'cve_id': 'CVE-2017-11503', 'min_version': '5.2.23', 'max_version': '5.2.23'}, {'cve_id': 'CVE-2016-10045', 'min_version': 'N/min', 'max_version': '5.2.20'}, {'cve_id': 'CVE-2016-10033', 'min_version': 'N/min', 'max_version': '5.2.18'}, {'cve_id': 'CVE-2007-3215', 'min_version': '1.7', 'max_version': '1.7'}, {'cve_id': 'CVE-2005-1807', 'min_version': 'N/min', 'max_version': '1.7.2'}]  # your CVE list
# target_version = "5.2.17"

# affected_cves = [
#     cve for cve in cve_list 
#     if is_version_affected(cve, target_version)
# ]

# print(f"affectedCVE: {affected_cves}")

# cve_lst = [item['cve_id'] for item in cve_list]
# print(cve_lst)
# for cve in affected_cves:
#     print(f"{cve['cve_id']}: {cve['min_version']} -> {cve['max_version']}")