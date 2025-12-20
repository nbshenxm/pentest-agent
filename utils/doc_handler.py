import os
import json
from utils.prompt import PentestAgentPrompt
from utils.dir_class import judge_class
from llama_index.llms.openai import OpenAI
from llama_index.core import (
    Settings,
    load_index_from_storage,
    StorageContext,
    SimpleDirectoryReader,
    SimpleKeywordTableIndex,
    SummaryIndex
)
from llama_index.core.schema import IndexNode
from llama_index.core.storage.index_store import SimpleIndexStore
from llama_index.core.query_engine import RetrieverQueryEngine
import dotenv
from utils.vote import vote, get_final_res
from functools import wraps
import multiprocessing

default_vul_type_conf = {
    "code_code_execution": "4",
    "code_privilege_escalation": "4",
    "code_info_leak": "4",
    "code_bypass": "4",
    "code_dos": "4"
}

default_exp_maturity_conf = {
    "code_poc": "4",
    "code_flexibility": "4",
    "code_functionality": "4"
}

default_isRemote_conf = "4"

default_attack_complexity_conf = {
    "code_attack_evasion": "4",
    "code_info_dependency": "4",
    "code_attack_condition": "4",
    "code_attack_probability": "4",
    "code_privilege_required": "4",
    "code_user_interaction": "4"
}

default_otpt = {
    "note": "timeout"
}

default_features = {
    "code_attack_evasion": "False",
    "code_info_dependency": "False",
    "code_attack_condition": "False",
    "code_attack_probability": "False",
    "code_privilege_required": "False",
    "code_user_interaction": "False"
}

def timeout(seconds, default_value=None):
    """a timeout decorator for process"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            def worker(result_queue, *args, **kwargs):
                try:
                    result = func(*args, **kwargs)
                    result_queue.put(result)
                except Exception as e:
                    result_queue.put({"error": str(e)})
            
            result_queue = multiprocessing.Queue()
            process = multiprocessing.Process(
                target=worker, 
                args=(result_queue, *args), 
                kwargs=kwargs
            )
            process.start()
            process.join(timeout=seconds)
            
            if process.is_alive():
                print(f"Function {func.__name__} timed out after {seconds} seconds, terminating...")
                process.terminate()
                process.join()
                return default_value
            else:
                if not result_queue.empty():
                    return result_queue.get()
                else:
                    return default_value
        return wrapper
    return decorator

class DocHandler:
    """ Given a data directory, DocHandler takes care of loading, indexing, and storing the data.
        Returns vector, summary, and keyword indices keyed by services
    """
    query_eng = None
    summary_dict = {}

    def __init__(self) -> None:

        pass
    
    def vul_analysis(self, cve:str, output_dir:str, vul_description:str):
        if "exploit" not in cve:    
            doc_dir = f"{output_dir}/{cve}/Google"
            code_dirs = {
                "ExploitDB": f"{output_dir}/{cve}/ExploitDB",
                "GitHub": f"{output_dir}/{cve}/GitHub"
            }
        else:
            doc_dir = f"{output_dir}/Google"
            code_dirs = {
                "ExploitDB": f"{output_dir}/ExploitDB",
                "GitHub": f"{output_dir}/GitHub"
            }
        
        result = {}
        result["code"] = {}
        result["doc"] = {}
        conf = {}
        conf["code"] = {}
        conf["doc"] = {}
        otpt = {}
        otpt["code"] = {}
        otpt["doc"] = {}

        # process code directories (ExploitDB and GitHub)
        for code_source, code_dir in code_dirs.items():
            if os.path.exists(code_dir) and len(os.listdir(code_dir)) > 0:
                if code_source not in result["code"]:
                    result["code"][code_source] = {
                        "lang_class": {},
                        "vul_type": {},
                        "exp_maturity": {},
                        "exp_flexibility": {},
                        "isRemote": {},
                        "attack_complexity": {}
                    }
                    vul_type_conf = {}
                    vul_type_otpt = {}
                    exp_maturity_conf = {}
                    exp_maturity_otpt = {}
                    isRemote_conf = {}
                    isRemote_otpt = {}
                    attack_complexity_conf = {}
                    attack_complexity_otpt = {}
                    conf["code"][code_source] = {
                        "vul_type": {},
                        "exp_maturity": {},
                        "isRemote": {},
                        "attack_complexity": {}
                    }
                    otpt["code"][code_source] = {
                        "vul_type": {},
                        "exp_maturity": {},
                        "isRemote": {},
                        "attack_complexity": {}
                    }
                
                subdirs = [f.name for f in os.scandir(code_dir) if f.is_dir()]
                for repo in subdirs:
                    repo_dir = os.path.join(code_dir, repo)
                    print(f"repo or dir: {repo}")
                    entries = [entry for entry in os.listdir(repo_dir) if not entry.startswith('.')]
                    if not os.path.exists(repo_dir) or len(entries) == 0:
                        continue
                    
                    code_reader = SimpleDirectoryReader(repo_dir, recursive=True, num_files_limit=10)
                    code_documents = code_reader.load_data()
                    repo_summary_index = SummaryIndex.from_documents(code_documents)
                    repo_query_engine = repo_summary_index.as_query_engine()

                    result["code"][code_source]["lang_class"][repo] = judge_class(repo_dir)
                    
                    vul_type, vul_type_conf, vul_type_otpt = self.get_vul_category_from_code(cve, repo_query_engine, repo, output_dir)
                    result["code"][code_source]["vul_type"][repo] = vul_type
                    
                    if repo == "Code_File":
                        result["code"][code_source]["exp_maturity"][repo] = "PoC"
                    else:
                        exp_maturity, exp_flexibility, exp_maturity_conf, exp_maturity_otpt = self.get_exp_maturity_analysis(cve, repo_query_engine, vul_description, repo, output_dir)
                        result["code"][code_source]["exp_maturity"][repo] = exp_maturity
                        result["code"][code_source]["exp_flexibility"][repo] = exp_flexibility
                    
                    isRemote, isRemote_conf, isRemote_otpt = self.get_isRemote_from_code(cve, repo_query_engine, repo, output_dir)
                    result["code"][code_source]["isRemote"][repo] = isRemote
                    
                    attack_complexity, attack_complexity_conf, attack_complexity_otpt = self.get_attack_complexity_from_code(cve, repo_query_engine, repo, output_dir)
                    result["code"][code_source]["attack_complexity"][repo] = attack_complexity

                    features_conf = {
                        "vul_type": vul_type_conf,
                        "exp_maturity": exp_maturity_conf,
                        "isRemote": isRemote_conf,
                        "attack_complexity": attack_complexity_conf
                    }

                    features_otpt = {
                        "vul_type": vul_type_otpt,
                        "exp_maturity": exp_maturity_otpt,
                        "isRemote": isRemote_otpt,
                        "attack_complexity": attack_complexity_otpt
                    }

                    if "exploit" in cve:
                        filename_conf = f"{output_dir}/conf_score_from_code_{repo}.json"
                        filename_otpt = f"{output_dir}/otpt_from_code_{repo}.json"
                    else:
                        filename_conf = f"{output_dir}/{cve}/conf_score_from_code_{repo}.json"
                        filename_otpt = f"{output_dir}/{cve}/otpt_from_code_{repo}.json"
                    with open(filename_conf, 'w') as f:
                        json.dump(features_conf, f, indent=4)
                    with open(filename_otpt, 'w') as f:
                        json.dump(features_otpt, f, indent=4)
        
        # process document directories
        if os.path.exists(doc_dir) and len(os.listdir(doc_dir)) > 0:
            doc_reader = SimpleDirectoryReader(doc_dir, recursive=True, num_files_limit=10)
            doc_documents = doc_reader.load_data()
            doc_summary_index = SummaryIndex.from_documents(doc_documents)
            doc_query_engine = doc_summary_index.as_query_engine()
            
            vul_type = self.get_vul_category_from_doc(cve, doc_query_engine, output_dir)
            result["doc"]["vul_type"] = vul_type
            
            isRemote = self.get_isRemote_from_doc(cve, doc_query_engine, output_dir)
            result["doc"]["isRemote"] = isRemote
            
            attack_complexity = self.get_attack_complexity_from_doc(cve, doc_query_engine, output_dir)
            result["doc"]["attack_complexity"] = attack_complexity

        return result

    @timeout(300, default_value=("Unknown", default_vul_type_conf, default_otpt))
    def get_vul_category_from_code(self, cve, query_engine, repo, output_dir):
        # print("called get_vul_category_from_code")
        code_code_execution_txt = "None"
        code_privilege_escalation_txt = "None"
        code_info_leak_txt = "None"
        code_bypass_txt = "None"
        code_dos_txt = "None"
        code_code_execution_conf = ""
        code_privilege_escalation_conf = ""
        code_info_leak_conf = ""
        code_bypass_conf = ""
        code_dos_conf = ""
        code_code_execution_otpt = ""
        code_privilege_escalation_otpt = ""
        code_info_leak_otpt = ""
        code_bypass_otpt = ""
        code_dos_otpt = ""
        try:
            code_code_execution_txt, code_code_execution_conf, code_code_execution_otpt = get_final_res(str(query_engine.query(PentestAgentPrompt.code_vul_code_execution_query)))
            code_privilege_escalation_txt, code_privilege_escalation_conf, code_privilege_escalation_otpt = get_final_res(str(query_engine.query(PentestAgentPrompt.code_vul_privilege_escalation_query)))
            code_info_leak_txt, code_info_leak_conf, code_info_leak_otpt = get_final_res(str(query_engine.query(PentestAgentPrompt.code_vul_information_leak_query)))
            code_bypass_txt, code_bypass_conf, code_bypass_otpt = get_final_res(str(query_engine.query(PentestAgentPrompt.code_vul_bypass_query)))
            code_dos_txt, code_dos_conf, code_dos_otpt = get_final_res(str(query_engine.query(PentestAgentPrompt.code_vul_denial_of_service_query)))
        except Exception as e:
            print(e)

        if "exploit" in cve:
            filename = f"{output_dir}/vul_impact_features_from_code_{repo}.json"
        else:
            filename = f"{output_dir}/{cve}/vul_impact_features_from_code_{repo}.json"
        with open(filename, 'w') as f:
            features = {
                "code_code_execution": code_code_execution_txt,
                "code_privilege_escalation": code_privilege_escalation_txt,
                "code_info_leak": code_info_leak_txt,
                "code_bypass": code_bypass_txt,
                "code_dos": code_dos_txt,
            }
            json.dump(features, f, indent=4)

        features_conf = {
                "code_code_execution": code_code_execution_conf,
                "code_privilege_escalation": code_privilege_escalation_conf,
                "code_info_leak": code_info_leak_conf,
                "code_bypass": code_bypass_conf,
                "code_dos": code_dos_conf,
            }
        
        features_otpt = {
                "code_code_execution": code_code_execution_otpt,
                "code_privilege_escalation": code_privilege_escalation_otpt,
                "code_info_leak": code_info_leak_otpt,
                "code_bypass": code_bypass_otpt,
                "code_dos": code_dos_otpt,
            }

        if code_code_execution_txt == "True":
            return "Code Execution", features_conf, features_otpt
        elif code_privilege_escalation_txt == "True":
            return "Privilege Escalation", features_conf, features_otpt
        elif code_info_leak_txt == "True":
            return "Information Leak", features_conf, features_otpt
        elif code_bypass_txt == "True":
            return "Bypass", features_conf, features_otpt
        if code_dos_txt == "True":
            return "Denial of Service", features_conf, features_otpt
        return "Unknown", features_conf, features_otpt

    
    def get_vul_category_from_doc(self, cve, query_engine, output_dir):
        doc_code_execution_txt = "None"
        doc_privilege_escalation_txt = "None"
        doc_info_leak_txt = "None"
        doc_bypass_txt = "None"
        doc_dos_txt = "None"
        try:
            doc_code_execution_txt = get_final_res(str(query_engine.query(PentestAgentPrompt.doc_vul_code_execution_query)))
            doc_privilege_escalation_txt = get_final_res(str(query_engine.query(PentestAgentPrompt.doc_vul_privilege_escalation_query)))
            doc_info_leak_txt = get_final_res(str(query_engine.query(PentestAgentPrompt.doc_vul_information_leak_query)))
            doc_bypass_txt = get_final_res(str(query_engine.query(PentestAgentPrompt.doc_vul_bypass_query)))
            doc_dos_txt = get_final_res(str(query_engine.query(PentestAgentPrompt.doc_vul_denial_of_service_query)))
        except Exception as e:
            print(e)

        if "exploit" in cve:
            filename = f"{output_dir}/vul_impact_features_from_doc.json"
        else:
            filename = f"{output_dir}/{cve}/vul_impact_features_from_doc.json"
        with open(filename, 'w') as f:
            features = {
                "doc_code_execution": doc_code_execution_txt,
                "doc_privilege_escalation": doc_privilege_escalation_txt,
                "doc_info_leak": doc_info_leak_txt,
                "doc_bypass": doc_bypass_txt,
                "doc_dos": doc_dos_txt,
            }
            json.dump(features, f, indent=4)

        if doc_code_execution_txt == "True":
            return "Code Execution"
        elif doc_privilege_escalation_txt == "True":
            return "Privilege Escalation"
        elif doc_info_leak_txt == "True":
            return "Information Leak"
        elif doc_bypass_txt == "True":
            return "Bypass"
        if doc_dos_txt == "True":
            return "Denial of Service"
        return "Unknown"
        
    @timeout(300, default_value=("None", "unflex", default_exp_maturity_conf, default_otpt))
    def get_exp_maturity_analysis(self, cve:str, query_engine, vul_impact:str, repo, output_dir):
        # print("called get_exp_maturity_analysis")
        code_description_txt = "None"
        code_poc_txt = "None"
        code_availability_txt = "None"
        code_flexibility_txt = "None"
        code_functionality_txt = "None"
        exp_maturity = "Unknown"
        exp_flexibility = "Unknown"
        code_poc_conf = ""
        code_flexibility_conf = ""
        code_functionality_conf = ""
        code_description_txt = ""
        code_poc_otpt = ""
        code_availability_txt = ""
        code_flexibility_otpt = ""
        code_functionality_otpt = ""
        exp_maturity = ""

        try:

            code_description_txt = str(query_engine.query(PentestAgentPrompt.code_description_query))
            code_poc_txt, code_poc_conf, code_poc_otpt = get_final_res(str(query_engine.query(PentestAgentPrompt.code_poc_query)))
            code_availability_txt = str(query_engine.query(PentestAgentPrompt.code_availability_query))
            code_flexibility_txt, code_flexibility_conf, code_flexibility_otpt = get_final_res(str(query_engine.query(PentestAgentPrompt.code_flexibility_query)))
            code_functionality_txt, code_functionality_conf, code_functionality_otpt = get_final_res(str(query_engine.query(PentestAgentPrompt.code_functionality_query)))

        except Exception as e:
            print(e)

        if code_poc_txt == "True":
            if code_availability_txt == "True" and code_functionality_txt == "True":
                exp_maturity = "Exploit"
            elif code_availability_txt == "False" and code_functionality_txt == "False":
                exp_maturity = "PoC"
            else:
                exp_maturity = "PoC+"
        else:
            exp_maturity = "None"

        if code_flexibility_txt == "True":
            exp_flexibility = "flex"
        else:
            exp_flexibility = "unflex"
        

        
        if "exploit" in cve:
            filename = f"{output_dir}/exp_maturity_features_{repo}.json"
        else:
            filename = f"{output_dir}/{cve}/exp_maturity_features_{repo}.json"
        with open(filename, 'w') as f:
            features = {
                "code_description": code_description_txt,
                "code_poc": code_poc_txt,
                "code_availability": code_availability_txt,
                "code_flexibility": code_flexibility_txt,
                "code_functionality": code_functionality_txt,
                "exp_maturity": exp_maturity,
            }
            json.dump(features, f, indent=4)

        features_conf = {
            "code_poc": code_poc_conf,
            "code_flexibility": code_flexibility_conf,
            "code_functionality": code_functionality_conf,
        }

        features_otpt = {
            "code_description": code_description_txt,
            "code_poc": code_poc_otpt,
            "code_availability": code_availability_txt,
            "code_flexibility": code_flexibility_otpt,
            "code_functionality": code_functionality_otpt,
            "exp_maturity": exp_maturity,
        }

        return exp_maturity, exp_flexibility, features_conf, features_otpt

    @timeout(300, default_value=("False", default_isRemote_conf, default_otpt))
    def get_isRemote_from_code(self, cve:str, query_engine, repo, output_dir):
        # print("called get_isRemote_from_code")
        code_isRemote_txt = "None"
        code_isRemote_conf = ""
        code_isRemote_otpt = ""
        try:
            code_isRemote_txt, code_isRemote_conf, code_isRemote_otpt = get_final_res(str(query_engine.query(PentestAgentPrompt.code_isRemote_query)))

        except Exception as e:
            print(e)
        
        if "exploit" in cve:
            filename = f"{output_dir}/isRemote_features_from_code_{repo}.json"
        else:
            filename = f"{output_dir}/{cve}/isRemote_features_from_code_{repo}.json"
        with open(filename, 'w') as f:
            features = {
                "code_isRemote": code_isRemote_txt,
            }
            json.dump(features, f, indent=4)

        return code_isRemote_txt, code_isRemote_conf, code_isRemote_otpt
    
    def get_isRemote_from_doc(self, cve:str, query_engine, output_dir):
        doc_isRemote_txt = "None"
        try:
            doc_isRemote_txt = get_final_res(str(query_engine.query(PentestAgentPrompt.doc_isRemote_query)))
        except Exception as e:
            print(e)

        if "exploit" in cve:
            filename = f"{output_dir}/isRemote_features_from_doc.json"
        else:
            filename = f"{output_dir}/{cve}/isRemote_features_from_doc.json"
        with open(filename, 'w') as f:
            features = {
                "doc_isRemote": doc_isRemote_txt,
            }
            json.dump(features, f, indent=4)

        return doc_isRemote_txt

    @timeout(300, default_value=(default_features, default_attack_complexity_conf, default_otpt))
    def get_attack_complexity_from_code(self, cve:str, query_engine, repo, output_dir):
        # print("called get_attack_complexity_from_code")
        code_attack_evasion_txt = "None"
        code_info_dependency_txt = "None"
        code_attack_condition_txt = "None"
        code_attack_probability_txt = "None"
        code_privilege_required_txt = "None"
        code_user_interaction_txt = "None"
        code_attack_evasion_conf = ""
        code_info_dependency_conf = ""
        code_attack_condition_conf = ""
        code_attack_probability_conf = ""
        code_privilege_required_conf = ""
        code_user_interaction_conf = ""
        code_attack_evasion_otpt = ""
        code_info_dependency_otpt = ""
        code_attack_condition_otpt = ""
        code_attack_probability_otpt = ""
        code_privilege_required_otpt = ""
        code_user_interaction_otpt = ""
        try:
            # code_attack_evasion_txt = str(query_engine.query(PentestAgentPrompt.code_attack_evasion_query))
            # print("code_attack_evasion_query:")
            code_attack_evasion_txt, code_attack_evasion_conf, code_attack_evasion_otpt = vote(query_engine, PentestAgentPrompt.code_attack_evasion_query, no_vote = 1, use_judge = True)
            # print("code_info_dependency_query:")
            code_info_dependency_txt, code_info_dependency_conf, code_info_dependency_otpt = vote(query_engine, PentestAgentPrompt.code_info_dependency_query, no_vote = 1)
            # print("code_attack_condition_query:")
            code_attack_condition_txt, code_attack_condition_conf, code_attack_condition_otpt = vote(query_engine, PentestAgentPrompt.code_attack_condition_query, no_vote = 1)
            # print("code_attack_probability_query:")
            code_attack_probability_txt, code_attack_probability_conf, code_attack_probability_otpt = vote(query_engine, PentestAgentPrompt.code_attack_probability_query, no_vote = 1, use_judge = True)
            # print("code_privilege_required_query:")
            code_privilege_required_txt, code_privilege_required_conf, code_privilege_required_otpt = vote(query_engine, PentestAgentPrompt.code_privilege_required_query, no_vote = 1)
            # print("code_user_interaction_query:")
            code_user_interaction_txt, code_user_interaction_conf, code_user_interaction_otpt = vote(query_engine, PentestAgentPrompt.code_user_interaction_query, no_vote = 1)

        except Exception as e:
            print(e)

        features = {
                "code_attack_evasion": code_attack_evasion_txt,
                "code_info_dependency": code_info_dependency_txt,
                "code_attack_condition": code_attack_condition_txt,
                "code_attack_probability": code_attack_probability_txt,
                "code_privilege_required": code_privilege_required_txt,
                "code_user_interaction": code_user_interaction_txt,
            }
        
        conf_score = {
            "code_attack_evasion": code_attack_evasion_conf if code_attack_evasion_conf else "3",
            "code_info_dependency": code_info_dependency_conf if code_info_dependency_conf else "3",
            "code_attack_condition": code_attack_condition_conf if code_attack_condition_conf else "3",
            "code_attack_probability": code_attack_probability_conf if code_attack_probability_conf else "3",
            "code_privilege_required": code_privilege_required_conf if code_privilege_required_conf else "3",
            "code_user_interaction": code_user_interaction_conf if code_user_interaction_conf else "3"
        }
        
        features_otpt = {
            "code_attack_evasion": code_attack_evasion_otpt,
            "code_info_dependency": code_info_dependency_otpt,
            "code_attack_condition": code_attack_condition_otpt,
            "code_attack_probability": code_attack_probability_otpt,
            "code_privilege_required": code_privilege_required_otpt,
            "code_user_interaction": code_user_interaction_otpt
        }
        
        feature_count = sum(value == "True" for value in features.values())

        if "exploit" in cve:
            filename_score = f"{output_dir}/attack_complexity_features_from_code_{repo}.json"
        else:
            filename_score = f"{output_dir}/{cve}/attack_complexity_features_from_code_{repo}.json"
        with open(filename_score, 'w') as f:
            json.dump(features, f, indent=4)

        return features, conf_score, features_otpt
    
    def get_attack_complexity_from_doc(self, cve:str, query_engine, output_dir):
        doc_attack_evasion_txt = "None"
        doc_info_dependency_txt = "None"
        doc_attack_condition_txt = "None"
        doc_attack_probability_txt = "None"
        doc_privilege_required_txt = "None"
        doc_user_interaction_txt = "None"
        doc_attack_evasion_conf = ""
        doc_info_dependency_conf = ""
        doc_attack_condition_conf = ""
        doc_attack_probability_conf = ""
        doc_privilege_required_conf = ""
        doc_user_interaction_conf = ""
        try:
            # print("doc_attack_evasion_query:")
            doc_attack_evasion_txt, doc_attack_evasion_conf = vote(query_engine, PentestAgentPrompt.doc_attack_evasion_query)
            # print("doc_info_dependency_query:")
            doc_info_dependency_txt, doc_info_dependency_conf = vote(query_engine, PentestAgentPrompt.doc_info_dependency_query)
            # print("doc_attack_condition_query:")
            doc_attack_condition_txt, doc_attack_condition_conf = vote(query_engine, PentestAgentPrompt.doc_attack_condition_query)
            # print("doc_attack_probability_query:")
            doc_attack_probability_txt, doc_attack_probability_conf = vote(query_engine, PentestAgentPrompt.doc_attack_probability_query)
            # print("doc_privilege_required_query:")
            doc_privilege_required_txt, doc_privilege_required_conf = vote(query_engine, PentestAgentPrompt.doc_privilege_required_query)
            # print("doc_user_interaction_query:")
            doc_user_interaction_txt, doc_user_interaction_conf = vote(query_engine, PentestAgentPrompt.doc_user_interaction_query)

        except Exception as e:
            print(e)

        features = {
                "doc_attack_evasion": doc_attack_evasion_txt,
                "doc_info_dependency": doc_info_dependency_txt,
                "doc_attack_condition": doc_attack_condition_txt,
                "doc_attack_probability": doc_attack_probability_txt,
                "doc_privilege_required": doc_privilege_required_txt,
                "doc_user_interaction": doc_user_interaction_txt,
            }
        
        conf_score = {
                "doc_attack_evasion": doc_attack_evasion_conf if doc_attack_evasion_conf else "3",
                "doc_info_dependency": doc_info_dependency_conf if doc_info_dependency_conf else "3",
                "doc_attack_condition": doc_attack_condition_conf if doc_attack_condition_conf else "3",
                "doc_attack_probability": doc_attack_probability_conf if doc_attack_probability_conf else "3",
                "doc_privilege_required": doc_privilege_required_conf if doc_privilege_required_conf else "3",
                "doc_user_interaction": doc_user_interaction_conf if doc_user_interaction_conf else "3"
            }
        
        feature_count = sum(value == "True" for value in features.values())

        if "exploit" in cve:
            filename_score = f"{output_dir}/attack_complexity_features_from_doc.json"
        else:
            filename_score = f"{output_dir}/{cve}/attack_complexity_features_from_doc.json"
        with open(filename_score, 'w') as f:            
            json.dump(features, f, indent=4)

        if "exploit" in cve:
            filename_conf = f"{output_dir}/attack_complexity_conf_score_from_doc.json"
        else:
            filename_conf = f"{output_dir}/{cve}/attack_complexity_conf_score_from_doc.json"
        with open(filename_conf, 'w') as f:            
            json.dump(conf_score, f, indent=4)

        return features

    def create_index(self, topic_dir:str, summary_prompt:str, keyword:str):
        list_subfolders_with_paths = [f.path for f in os.scandir(topic_dir) if f.is_dir()]
        counter = 0
        repo_index_nodes = []
        keyword_index_dir_by_keyword = os.path.join(os.getenv("INDEX_STORAGE_DIR"),
                                                    "keyword_repos", keyword)
        repos_keyword_index = None
        
        if not os.path.exists(keyword_index_dir_by_keyword):
            for repo_dir in list_subfolders_with_paths:
                items = os.listdir(repo_dir)
                visible_items = [item for item in items if not item.startswith('.')]
                if visible_items:
                    print(repo_dir)

                    reader = SimpleDirectoryReader(repo_dir, recursive=True)
                    documents = reader.load_data()
                    repo_summary_index = SummaryIndex.from_documents(documents)
                    repo_query_engine = repo_summary_index.as_query_engine()
                    summary_txt = str(repo_query_engine.query(summary_prompt))
                    print(summary_txt)
                    self.summary_dict[repo_dir] = summary_txt

                    new_metadata = {
                        "repo path": str(repo_dir),}

                    repo_index_node = IndexNode(
                        text = summary_txt,
                        metadata = new_metadata,
                        index_id=str(counter)
                    )
                    repo_index_nodes.append(repo_index_node)

                    counter+=1

            repos_keyword_index = SimpleKeywordTableIndex(objects=repo_index_nodes)
            storage_context = StorageContext.from_defaults(index_store=SimpleIndexStore())
            repos_keyword_index.storage_context.persist(persist_dir=keyword_index_dir_by_keyword)
            
        else:
            storage_context = StorageContext.from_defaults(persist_dir=keyword_index_dir_by_keyword)
            repos_keyword_index = load_index_from_storage(storage_context)

        keyword_retriever = repos_keyword_index.as_retriever(verbose=True)


        self.query_eng = RetrieverQueryEngine.from_args(keyword_retriever, verbose=True)

    def query(self, query_content):
        response = self.query_eng.query(query_content)
        return response
    
    def get_repo_summary(self, repo_dir):
        return self.summary_dict[repo_dir]
    
    def get_repo_summaryDict(self):
        return self.summary_dict

def main():
    dotenv.load_dotenv()
    Settings.llm = OpenAI(temperature=0, model="gpt-4o")
    doc_dir = 'resources/CVE-2019-1609/GitHub'
    summary_prompt = PentestAgentPrompt.repo_summary
    doc_handler = DocHandler()
    doc_handler.create_index(doc_dir, summary_prompt, "CVE-2019-1609_github")
    service = "Cisco"
    version = ""
    query_content = f"Clearly list out paths of all relevant repositories that contains exploit poc applicable to {service} version {version}\
                    and provide the reasons to support each selection. \
                    To compare versions, you can compare their version numbers in left-to-right order. For example, 7.4.0 is an earlier version than 8.2.3.\
                    Make the selections by checking whether {version} is within the applicable version of the exploit. Only consider the paths mentioned in the context."
    res = doc_handler.query(query_content)
    print("response:")
    print(res)

if __name__ == "__main__":
    main()