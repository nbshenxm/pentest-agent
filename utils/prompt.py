import dataclasses
from . import prompts

@dataclasses.dataclass
class PentestAgentPrompt:

    repo_summary: str = prompts.REPO_SUMMARY
    
    recon_init: str = prompts.RECON_INIT
    
    recon_summary: str = prompts.RECON_SUMMARY
      
    search_agent_summary: str = prompts.SEARCH_AGENT_SUMMARY

    webpage_impl_summary: str = prompts.WEBPAGE_IMPL_SUMMARY
    
    execution_init_exploit_analysis: str = prompts.EXECUTION_INIT_EXPLOIT_ANALYSIS

    execution_step_by_step_guide: str = prompts.EXECUTION_STEP_BY_STEP_GUIDE

    execution_summary: str = prompts.EXECUTION_SUMMARY

    code_vul_code_execution_query: str = prompts.CODE_VUL_CODE_EXECUTION_QUERY

    doc_vul_code_execution_query: str = prompts.DOC_VUL_CODE_EXECUTION_QUERY

    code_vul_privilege_escalation_query: str = prompts.CODE_VUL_PRIVILEGE_ESCALATION_QUERY

    doc_vul_privilege_escalation_query: str = prompts.DOC_VUL_PRIVILEGE_ESCALATION_QUERY

    code_vul_information_leak_query: str = prompts.CODE_VUL_INFORMATION_LEAK_QUERY
    
    doc_vul_information_leak_query: str = prompts.DOC_VUL_INFORMATION_LEAK_QUERY

    code_vul_bypass_query: str = prompts.CODE_VUL_BYPASS_QUERY

    doc_vul_bypass_query: str = prompts.DOC_VUL_BYPASS_QUERY

    code_vul_denial_of_service_query: str = prompts.CODE_VUL_DENIAL_OF_SERVICE_QUERY

    doc_vul_denial_of_service_query: str = prompts.DOC_VUL_DENIAL_OF_SERVICE_QUERY

    base_judge_query_1: str = prompts.BASE_JUDGE_QUERY_1

    base_judge_query_2: str = prompts.BASE_JUDGE_QUERY_2

    code_attack_evasion_query: str = prompts.CODE_ATTACK_EVASION_QUERY

    doc_attack_evasion_query: str = prompts.DOC_ATTACK_EVASION_QUERY

    code_info_dependency_query: str = prompts.CODE_INFO_DEPENDENCY_QUERY
    
    doc_info_dependency_query: str = prompts.DOC_INFO_DEPENDENCY_QUERY

    code_attack_condition_query: str = prompts.CODE_ATTACK_CONDITION_QUERY

    doc_attack_condition_query: str = prompts.DOC_ATTACK_CONDITION_QUERY

    code_attack_probability_query: str = prompts.CODE_ATTACK_PROBABILITY_QUERY
    
    doc_attack_probability_query: str = prompts.DOC_ATTACK_PROBABILITY_QUERY
                                        

    # Privileges Required: None, Low, High
    code_privilege_required_query: str = prompts.CODE_PRIVILEGE_REQUIRED_QUERY
    
    doc_privilege_required_query: str = prompts.DOC_PRIVILEGE_REQUIRED_QUERY

    # User Interaction: None, Required
    code_user_interaction_query: str = prompts.CODE_USER_INTERACTION_QUERY
    
    doc_user_interaction_query: str = prompts.DOC_USER_INTERACTION_QUERY
    
    code_isRemote_query: str = prompts.CODE_ISREMOTE_QUERY

    doc_isRemote_query: str = prompts.DOC_ISREMOTE_QUERY
    
    code_description_query: str = prompts.CODE_DESCRIPTION_QUERY
    
    code_poc_query: str = prompts.CODE_POC_QUERY

    code_flexibility_query: str = prompts.CODE_FLEXIBILITY_QUERY

    code_functionality_query: str = prompts.CODE_FUNCTIONALITY_QUERY

    code_availability_query: str = prompts.CODE_AVAILABILITY_QUERY

