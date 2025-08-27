import os
import json
# from github_searcher import GithubSearcher
from utils.prompt import PentestAgentPrompt
from utils.dir_class import judge_class
from llama_index.llms.openai import OpenAI
from llama_index.llms.huggingface import HuggingFaceLLM
from llama_index.llms.huggingface_api import HuggingFaceInferenceAPI
from llama_index.embeddings.openai import OpenAIEmbedding
from llama_index.agent.openai import OpenAIAgent
from llama_index.core import (
    Settings,
    load_index_from_storage,
    StorageContext,
    SimpleDirectoryReader,
    VectorStoreIndex,
    SimpleKeywordTableIndex,
    SummaryIndex
)
from llama_index.core.vector_stores import (
    FilterOperator,
    FilterCondition,
    MetadataFilter,
    MetadataFilters,
)
from llama_index.core.schema import IndexNode
from llama_index.core.storage.index_store import SimpleIndexStore
from llama_index.core.vector_stores import SimpleVectorStore, MetadataInfo, VectorStoreInfo
from llama_index.core.query_engine import RetrieverQueryEngine
import dotenv
import nest_asyncio
from utils.vote import vote, get_final_res


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
        
        # process code directories (ExploitDB and GitHub)
        for code_source, code_dir in code_dirs.items():
            if os.path.exists(code_dir) and len(os.listdir(code_dir)) > 0:
                if code_source not in result["code"]:
                    result["code"][code_source] = {
                        "lang_class": {},
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
                    
                    vul_type = self.get_vul_category_from_code(cve, repo_query_engine, repo, output_dir)
                    result["code"][code_source]["vul_type"][repo] = vul_type
                    
                    if repo == "Code_File":
                        result["code"][code_source]["exp_maturity"][repo] = "PoC"
                    else:
                        exp_maturity = self.get_exp_maturity_analysis(cve, repo_query_engine, vul_description, repo, output_dir)
                        result["code"][code_source]["exp_maturity"][repo] = exp_maturity
                    
                    isRemote = self.get_isRemote_from_code(cve, repo_query_engine, repo, output_dir)
                    result["code"][code_source]["isRemote"][repo] = isRemote
                    
                    attack_complexity = self.get_attack_complexity_from_code(cve, repo_query_engine, repo, output_dir)
                    result["code"][code_source]["attack_complexity"][repo] = attack_complexity
        
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

    def get_vul_category_from_code(self, cve, query_engine, repo, output_dir):
        code_code_execution_txt = "None"
        code_privilege_escalation_txt = "None"
        code_info_leak_txt = "None"
        code_bypass_txt = "None"
        code_dos_txt = "None"
        try:
            code_code_execution_txt = get_final_res(str(query_engine.query(PentestAgentPrompt.code_vul_code_execution_query)))
            code_privilege_escalation_txt = get_final_res(str(query_engine.query(PentestAgentPrompt.code_vul_privilege_escalation_query)))
            code_info_leak_txt = get_final_res(str(query_engine.query(PentestAgentPrompt.code_vul_information_leak_query)))
            code_bypass_txt = get_final_res(str(query_engine.query(PentestAgentPrompt.code_vul_bypass_query)))
            code_dos_txt = get_final_res(str(query_engine.query(PentestAgentPrompt.code_vul_denial_of_service_query)))
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

        if code_code_execution_txt == "True":
            return "Code Execution"
        elif code_privilege_escalation_txt == "True":
            return "Privilege Escalation"
        elif code_info_leak_txt == "True":
            return "Information Leak"
        elif code_bypass_txt == "True":
            return "Bypass"
        if code_dos_txt == "True":
            return "Denial of Service"
        return "Unknown"

    
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
        
    def get_exp_maturity_analysis(self, cve:str, query_engine, vul_impact:str, repo, output_dir):
        code_description_txt = "None"
        code_poc_txt = "None"
        code_availability_txt = "None"
        code_flexibility_txt = "None"
        code_functionality_txt = "None"
        exp_maturity = "Unknown"

        try:

            code_description_txt = str(query_engine.query(PentestAgentPrompt.code_description_query))
            code_poc_txt = get_final_res(str(query_engine.query(PentestAgentPrompt.code_poc_query)))
            code_availability_txt = str(query_engine.query(PentestAgentPrompt.code_availability_query))
            code_flexibility_txt = get_final_res(str(query_engine.query(PentestAgentPrompt.code_flexibility_query)))
            code_functionality_txt = get_final_res(str(query_engine.query(PentestAgentPrompt.code_functionality_query)))

        except Exception as e:
            print(e)

        if code_poc_txt == "True":
            exp_maturity = "PoC"
            if (code_availability_txt == "True" or code_flexibility_txt == "True") and code_functionality_txt == "True":
                exp_maturity = "Exploit"
        else:
            exp_maturity = "None"
        
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

        return exp_maturity

    def get_isRemote_from_code(self, cve:str, query_engine, repo, output_dir):
        code_isRemote_txt = "None"
        try:
            code_isRemote_txt = get_final_res(str(query_engine.query(PentestAgentPrompt.code_isRemote_query)))

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

        return code_isRemote_txt
    
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

    def get_attack_complexity_from_code(self, cve:str, query_engine, repo, output_dir):
        code_attack_evasion_txt = "None"
        code_info_dependency_txt = "None"
        code_attack_condition_txt = "None"
        code_attack_probability_txt = "None"
        code_privilege_required_txt = "None"
        code_user_interaction_txt = "None"
        try:
            # code_attack_evasion_txt = str(query_engine.query(PentestAgentPrompt.code_attack_evasion_query))
            # print("code_attack_evasion_query:")
            code_attack_evasion_txt = vote(query_engine, PentestAgentPrompt.code_attack_evasion_query, no_vote = 4, use_judge = True)
            # print("code_info_dependency_query:")
            code_info_dependency_txt = vote(query_engine, PentestAgentPrompt.code_info_dependency_query)
            # print("code_attack_condition_query:")
            code_attack_condition_txt = vote(query_engine, PentestAgentPrompt.code_attack_condition_query)
            # print("code_attack_probability_query:")
            code_attack_probability_txt = vote(query_engine, PentestAgentPrompt.code_attack_probability_query, no_vote = 4, use_judge = True)
            # print("code_privilege_required_query:")
            code_privilege_required_txt = vote(query_engine, PentestAgentPrompt.code_privilege_required_query)
            # print("code_user_interaction_query:")
            code_user_interaction_txt = vote(query_engine, PentestAgentPrompt.code_user_interaction_query)

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
        
        feature_count = sum(value == "True" for value in features.values())

        if "exploit" in cve:
            filename = f"{output_dir}/attack_complexity_features_from_code_{repo}.json"
        else:
            filename = f"{output_dir}/{cve}/attack_complexity_features_from_code_{repo}.json"
        with open(filename, 'w') as f:
            json.dump(features, f, indent=4)

        return features
    
    def get_attack_complexity_from_doc(self, cve:str, query_engine, output_dir):
        doc_attack_evasion_txt = "None"
        doc_info_dependency_txt = "None"
        doc_attack_condition_txt = "None"
        doc_attack_probability_txt = "None"
        doc_privilege_required_txt = "None"
        doc_user_interaction_txt = "None"
        try:
            # print("doc_attack_evasion_query:")
            doc_attack_evasion_txt = vote(query_engine, PentestAgentPrompt.doc_attack_evasion_query)
            # print("doc_info_dependency_query:")
            doc_info_dependency_txt = vote(query_engine, PentestAgentPrompt.doc_info_dependency_query)
            # print("doc_attack_condition_query:")
            doc_attack_condition_txt = vote(query_engine, PentestAgentPrompt.doc_attack_condition_query)
            # print("doc_attack_probability_query:")
            doc_attack_probability_txt = vote(query_engine, PentestAgentPrompt.doc_attack_probability_query)
            # print("doc_privilege_required_query:")
            doc_privilege_required_txt = vote(query_engine, PentestAgentPrompt.doc_privilege_required_query)
            # print("doc_user_interaction_query:")
            doc_user_interaction_txt = vote(query_engine, PentestAgentPrompt.doc_user_interaction_query)

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
        
        feature_count = sum(value == "True" for value in features.values())

        if "exploit" in cve:
            filename = f"{output_dir}/attack_complexity_features_from_doc.json"
        else:
            filename = f"{output_dir}/{cve}/attack_complexity_features_from_doc.json"
        with open(filename, 'w') as f:            
            json.dump(features, f, indent=4)

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