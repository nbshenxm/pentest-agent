# from github_searcher import GithubSearcher
# from google_searcher import GoogleSearcher
import tiktoken
from llama_index.core.callbacks import CallbackManager, TokenCountingHandler
from utils.doc_handler import DocHandler
from llama_index.llms.openai import OpenAI
from llama_index.llms.langchain import LangChainLLM
from llama_index.llms.huggingface import HuggingFaceLLM
from llama_index.llms.huggingface_api import HuggingFaceInferenceAPI
from llama_index.core import Settings
import subprocess
import os
import openai
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch
import pandas as pd
from sklearn.metrics import confusion_matrix, cohen_kappa_score
from sklearn.preprocessing import MinMaxScaler, StandardScaler, RobustScaler
import seaborn as sns
import matplotlib.pyplot as plt
from scipy.stats import pearsonr, spearmanr
from itertools import combinations
import numpy as np
import json
import logging
import time
from tqdm import tqdm
from utils.searchers.search_once import compose
import re
import yaml
from utils.model_manager import get_model
logger = logging.getLogger(__name__)

config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'configs', 'config.yaml')
with open(config_path, 'r', encoding='utf-8') as f:
    config = yaml.safe_load(f)
planning_config = config['runtime']['planning']

def cvemap_search(cve, info_dir):
    cvemap_json_path = f"{info_dir}/cvemap.json"
    cvemap_command = f"echo {cve} | cvemap -json > {cvemap_json_path}"
    shell_result = subprocess.run(cvemap_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=50)
    with open(cvemap_json_path) as f:
        json_data = json.load(f)
        # print(json_data)
        if len(json_data) == 0:
            logging.error(f"Error in cvemap search: {cve}")
            return None
        return json_data[0]

def searchsploit_search(cve):
    searchsploit_json_path = f"resources/{cve}/exploitdb.json"
    searchsploit_command = f"searchsploit {cve} -j > {searchsploit_json_path}"
    shell_result = subprocess.run(searchsploit_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=50)
    with open(searchsploit_json_path) as f:
        json_data = json.load(f)
        # print(json_data)
        return json_data
    

def categorize_cvss(cvss_score):
    if not (0.0 <= cvss_score <= 10.0):
        return "value not in range"

    if cvss_score < 4.0:
        return "hard"
    elif 4.0 <= cvss_score < 7.0:
        return "medium"
    else:
        return "easy"
    
def categorize_epss(epss_score):
    if not (0.0 <= epss_score <= 1.0):
        return "value not in range"

    if epss_score < 0.4:
        return "hard"
    elif 0.4 <= epss_score < 0.94:
        return "medium"
    else:
        return "easy"
    
def count_cwe(cve_lst):
    
    cwe_dict = {}
    for cve in cve_lst:
        info_dir = f"resources/{cve}/info"
        cvemap_json_path = f"{info_dir}/cvemap.json"
        with open(cvemap_json_path) as f:
            cvemap_json = json.load(f)[0]
            cwe_lst = cvemap_json.get('weaknesses', [])
            for cwe in cwe_lst:
                cwe_id = cwe['cwe_id']
                if cwe_id in cwe_dict:
                    cwe_dict[cwe_id] += 1
                else:
                    cwe_dict[cwe_id] = 1
    return cwe_dict

def calculate_score(features, trending_score):
    weights = config['cve_scoring']['weights']

    scores = {}
    max_score_github = 0
    max_score_repo_github = None
    max_score_expdb = 0
    max_score_repo_expdb = None
    max_score = 0
    max_score_repo = None
    final_score = 0
    has_code = False

    code_sources = ["GitHub", "ExploitDB"]

    if features['code'].get('GitHub') or features['code'].get('ExploitDB'):
        for source in code_sources:
            if not features['code'].get(source):
                continue  # if not have data from source, skip

            has_code = True
            for repo, vul_type in features['code'][source]["vul_type"].items():
                score = 0
                
                # Calculate scores for each field
                score += weights["vul_type"].get(vul_type, 0)
                score += weights["isRemote"].get(features['code'][source]["isRemote"].get(repo, ""), 0)
                
                # Attack complexity fields
                attack_complexity = features['code'][source]["attack_complexity"].get(repo, {})
                for field, value in attack_complexity.items():
                    score += 1 * weights["attack_complexity"].get(field, {}).get(value, 0)
                
                if repo == "Code_File":
                    score = score / 2

                score *= weights["exp_maturity"].get(features['code'][source]["exp_maturity"].get(repo, ""), 0)

                score *= weights["lang_class"].get(features['code'][source]["lang_class"].get(repo, ""), 1)

                if source == "GitHub":
                    score *= weights["source_weights"]["gthb"]
                elif source == "ExploitDB":
                    score *= weights["source_weights"]["expdb"]

                # Store the score
                scores[repo] = score

                # Check for max score
                if repo.isdigit():  # ExploitDB
                    if score >= max_score_expdb:
                        max_score_expdb = score
                        max_score_repo_expdb = repo
                else:  # GitHub
                    if score >= max_score_github:
                        max_score_github = score
                        max_score_repo_github = repo

        if max_score_expdb > max_score_github:
            max_score_repo = max_score_repo_expdb
            max_score = max_score_expdb
        else:
            max_score_repo = max_score_repo_github
            max_score = max_score_github

        if has_code:
            sorted_scores = sorted(scores.items(), key=lambda item: item[1], reverse=True)

            if trending_score == 999:
                trending_score_github = 0
                trending_score_expdb = weights["expdb_default_score"]
            else:
                trending_score_github = trending_score
                if features['code'].get('ExploitDB'):
                    trending_score_expdb = weights["expdb_default_score"]
                else: trending_score_expdb = 0

            # Add weighted trending score to the max score
            trend_score_weighted_expdb = trending_score_expdb * weights["trending_score"]
            trend_score_weighted_github = trending_score_github * weights["trending_score"]
    
            # Handle cases where one source has no scores
            final_expdb = (max_score_expdb + trend_score_weighted_expdb) if max_score_expdb > 0 else 0
            final_github = (max_score_github + trend_score_weighted_github) if max_score_github > 0 else 0

            final_score = max(final_expdb, final_github)

        return sorted_scores, max_score_repo, max_score, final_score, has_code
    
    elif features['doc']:
        doc_score = 0
        doc_score += weights["vul_type"].get(features["doc"]["vul_type"], 0)
        doc_score += weights["isRemote"].get(features["doc"]["isRemote"], 0)

        # Attack complexity fields for 'doc'
        for field, value in features["doc"]["attack_complexity"].items():
            doc_score += weights["attack_complexity"].get(field, {}).get(value, 0)

        doc_score *= weights["source_weights"]["gg"]
        
        scores["doc"] = doc_score

        # Check if 'doc' has the max score
        if doc_score > max_score:
            max_score = doc_score
            max_score_repo = "doc"

        return scores, max_score_repo, max_score, max_score, has_code
    else:
        return None, None, max_score, final_score, has_code
    
def calculate_match_stats(values1, values2):
    total = len(values1)
    exact_matches = sum(v1 == v2 for v1, v2 in zip(values1, values2))
    near_matches = sum(
        abs(['easy', 'medium', 'hard'].index(v1) - ['easy', 'medium', 'hard'].index(v2)) == 1
        for v1, v2 in zip(values1, values2)
    )
    mismatches = total - exact_matches - near_matches
    return {
        "Exact Match (%)": (exact_matches / total) * 100,
        "Near Match (%)": (near_matches / total) * 100,
        "Mismatch (%)": (mismatches / total) * 100,
    }

def create_df(cvss_data, epss_data, pentestasst_data):
    all_keys = sorted(set(cvss_data.keys()).union(epss_data.keys(), pentestasst_data.keys()))
    data = {
        'CVSS': [cvss_data.get(key, np.nan) for key in all_keys],
        'EPSS': [epss_data.get(key, np.nan) for key in all_keys],
        'EEAS': [pentestasst_data.get(key, np.nan) for key in all_keys],
    }
    df = pd.DataFrame(data, index=all_keys)
    return df

def normalize_data(df):
    if len(df) == 1:
        # for the case of a single value, directly return 0.5 or keep the original value
        df[['EEAS']] = 0.5  # or df[['EEAS']]
    else:
        scaler = StandardScaler()
        minmax_scaler = MinMaxScaler()
        df[['EEAS']] = minmax_scaler.fit_transform(scaler.fit_transform(df[['EEAS']]))
    normalized_df = pd.DataFrame(df, index=df.index, columns=df.columns)
    return normalized_df
    
def bin_agreement_analysis(df):
    pairwise_stats = {}
    for (name1, col1), (name2, col2) in combinations(df.items(), 2):
        # Calculate confusion matrix
        cm = confusion_matrix(col1, col2, labels=['easy', 'medium', 'hard'])
        kappa = cohen_kappa_score(col1, col2, labels=['easy', 'medium', 'hard'])
        stats = calculate_match_stats(col1, col2)

        pairwise_stats[f"{name1} vs {name2}"] = {
            "Confusion Matrix": cm.tolist(),
            "CohenS Kappa": kappa,
            **stats,
        }

    # Display results
    for pair, results in pairwise_stats.items():
        print(f"\nPairwise comparison: {pair}")
        print(f"Confusion Matrix:\n{np.array(results['Confusion Matrix'])}")
        print(f"Cohen's Kappa: {results['CohenS Kappa']:.4f}")
        print(f"Exact Match (%): {results['Exact Match (%)']:.2f}")
        print(f"Near Match (%): {results['Near Match (%)']:.2f}")
        print(f"Mismatch (%): {results['Mismatch (%)']:.2f}")

    return df

def num_agreement_analysis(df):
    stats = {}
    for col1, col2 in combinations(df.columns, 2):
        mean_values = (df[col1] + df[col2]) / 2
        diff_values = df[col1] - df[col2]

        mean_diff = np.mean(diff_values)
        std_diff = np.std(diff_values)

        print(f"diff mean: {np.mean(diff_values)}")
        print(f"diff std: {np.std(diff_values)}")

        threshold = 1.96 * std_diff
        diff_condition = abs(df[col1] - df[col2]) > threshold

        rows_large_diff = df[diff_condition]
        print(f"Rows where the difference between {col1} and {col2} is larger than {threshold}:")
        print(rows_large_diff)
        print(f"Total rows: {len(df)}, Rows with large difference: {len(rows_large_diff)}, percentage: {len(rows_large_diff)/len(df) * 100}%")
        
        values1, values2 = df[col1], df[col2]
        pearson_corr, _ = pearsonr(values1, values2)
        spearman_corr, _ = spearmanr(values1, values2)
        mae = np.mean(np.abs(values1 - values2))
        rmse = np.sqrt(np.mean((values1 - values2) ** 2))
        stats[f"{col1} vs {col2}"] = {
            "Pearson Correlation": pearson_corr,
            "Spearman Correlation": spearman_corr,
            "Mean Absolute Error (MAE)": mae,
            "Root Mean Squared Error (RMSE)": rmse,
        }

    for pair, metrics in stats.items():
        print(f"\nAgreement Analysis for {pair}:")
        for metric, value in metrics.items():
            print(f"{metric}: {value:.4f}")

    return df

def visualize_num_results(df, output_dir="plots/"):

    plt.rc('font', size=14) 

    # Pairwise scatter plots
    pairplot = sns.pairplot(df, kind="reg", diag_kind="kde")
    pairplot.savefig(os.path.join(output_dir, "pairwise_scatter_plots.pdf"))
    plt.close()

    # Heatmap for correlation
    correlation_matrix = df.corr()
    plt.figure(figsize=(8, 6))
    sns.heatmap(correlation_matrix, annot=True, cmap="coolwarm", fmt=".2f")
    plt.title("Heatmap of Correlations")
    plt.savefig(os.path.join(output_dir, "correlation_heatmap.pdf"))
    plt.close()

    # Bland-Altman plots
    for col1, col2 in combinations(df.columns, 2):
        mean_values = (df[col1] + df[col2]) / 2
        diff_values = df[col1] - df[col2]

        plt.figure(figsize=(8, 6))
        plt.scatter(mean_values, diff_values, alpha=0.7)
        plt.axhline(np.mean(diff_values), color='red', linestyle='--', label='Mean Difference')
        plt.axhline(np.mean(diff_values) + 1.96 * np.std(diff_values), color='blue', linestyle='--', label='±1.96SD')
        plt.axhline(np.mean(diff_values) - 1.96 * np.std(diff_values), color='blue', linestyle='--', label=None)
        plt.title(f"Bland-Altman Plot: {col1} vs {col2}", weight='bold')
        plt.xlabel('Mean of Two Measurements', weight='bold')
        plt.ylabel('Difference', weight='bold')
        plt.legend()
        filename = f"bland_altman_{col1}_vs_{col2}.pdf"
        plt.savefig(os.path.join(output_dir, filename))
        plt.close()

def visualize_bin_results(cvss_data, epss_data, pentestasst_data, output_dir):
    # Confusion Matrix Heatmap
    for (name1, data1), (name2, data2) in combinations([("CVSS", cvss_data), ("EPSS", epss_data), ("EEAS", pentestasst_data)], 2):
        labels = ['easy', 'medium', 'hard']
        confusion = confusion_matrix(list(data1.values()), list(data2.values()), labels=labels)
        
        plt.figure(figsize=(6, 5))
        sns.heatmap(confusion, annot=True, fmt="d", cmap="Blues", xticklabels=labels, yticklabels=labels)
        plt.title(f"Confusion Matrix: {name1} vs {name2}")
        plt.xlabel(f"{name2} Predictions")
        plt.ylabel(f"{name1} Predictions")
        plt.savefig(f"{output_dir}/confusion_matrix_{name1}_vs_{name2}.pdf")
        plt.close()

    # Bar Chart of Class Distributions
    data = {
        "Category": ['easy', 'medium', 'hard'],
        "CVSS": [list(cvss_data.values()).count(c) for c in ['easy', 'medium', 'hard']],
        "EPSS": [list(epss_data.values()).count(c) for c in ['easy', 'medium', 'hard']],
        "EEAS": [list(pentestasst_data.values()).count(c) for c in ['easy', 'medium', 'hard']],
    }
    df = pd.DataFrame(data).set_index("Category")
    
    df.plot(kind="bar", figsize=(8, 6))
    plt.title("Class Distributions Across Dictionaries")
    plt.ylabel("Frequency")
    plt.xlabel("Category")
    plt.xticks(rotation=0)
    plt.savefig(f"{output_dir}/class_distributions.pdf")
    plt.close()

    # Pairwise Agreement Bar Chart
    pairwise_agreements = []
    for (name1, data1), (name2, data2) in combinations([("CVSS", cvss_data), ("EPSS", epss_data), ("EEAS", pentestasst_data)], 2):
        total = len(data1)
        exact_matches = sum(1 for k in data1 if data1[k] == data2[k])
        near_matches = sum(1 for k in data1 if abs(['easy', 'medium', 'hard'].index(data1[k]) -
                                                   ['easy', 'medium', 'hard'].index(data2[k])) == 1)
        mismatches = total - exact_matches - near_matches

        pairwise_agreements.append({
            "Pair": f"{name1} vs {name2}",
            "Exact Matches (%)": exact_matches / total * 100,
            "Near Matches (%)": near_matches / total * 100,
            "Mismatches (%)": mismatches / total * 100
        })

    pairwise_df = pd.DataFrame(pairwise_agreements).set_index("Pair")
    pairwise_df.plot(kind="bar", stacked=True, figsize=(10, 6))
    plt.title("Pairwise Agreement Percentages")
    plt.ylabel("Percentage")
    plt.xlabel("Pairwise Comparison")
    plt.xticks(rotation=0)
    plt.legend(loc="upper right")
    plt.savefig(f"{output_dir}/pairwise_agreements.pdf")
    plt.close()
    
def cve_classifier(cve, output_dir="resources/", mode = "specific"):
    trending_score_path = f"{output_dir}/{cve}/Trend_Score.json"
    feature_path = f"{output_dir}/{cve}/features.json"
    cvemap_path = f"{output_dir}/{cve}/info/cvemap.json"
    result = None
    with open(feature_path, 'r') as f:
        result = json.load(f)
    trending_score = 0
    if result['code'].get('GitHub'):
        try:
            with open(trending_score_path, 'r') as f:
                _trending_score = json.load(f)
                # print(trending_score)
                trending_score = min(_trending_score.get("trend_score", 0), 50)
        except:
            logging.warning(f"Trending score not found for {cve}")
    else:
        trending_score = 999

    if mode == "specific":
        cvemap_json = None
        with open(cvemap_path, 'r') as f:
            cvemap_json = json.load(f)[0]
        cvss_score = cvemap_json.get('cvss_score', 0)
        epss_score = cvemap_json['epss']['epss_score']
        epss_percentile = cvemap_json['epss']['epss_percentile']
    elif mode == "general":
        cvss_score = 0
        epss_score = 0
        epss_percentile = 0
    cvss_category = categorize_cvss(cvss_score)
    epss_category = categorize_epss(epss_percentile)

    scores, max_score_repo, max_score, final_score, has_code = calculate_score(result, trending_score)

    exploitability = "hard"
    if final_score is not None and final_score > 0:
        if final_score > 50:    
            exploitability = "easy"
        elif final_score > 35:
            exploitability = "medium"
        else:
            exploitability = "hard"
    

    with open(f"{output_dir}/{cve}/classification.json", 'w') as f:
        classification = {
            "cvss_category": cvss_category,
            "epss_category": epss_category,
            "exploitability": exploitability,
            "final_score": final_score,
            "max_score_repo": max_score_repo,
            "max_score": max_score,
            "scores": scores,
            "has_code": has_code
        }
        json.dump(classification, f, indent=4)

    return cvss_score, cvss_category, epss_percentile, epss_category, final_score, exploitability, has_code

def cve_analysis(cve, output_dir="resources/"):
    cve_dir = f"{output_dir}/{cve}"
    info_dir = f"{output_dir}/{cve}/info"
    searching_start_time = time.time()
    compose(output_dir, cve)
    if not os.path.exists(info_dir):
        os.mkdir(info_dir)
    cvemap_json = cvemap_search(cve, info_dir)
    if cvemap_json is None:
        return 0
    cve_description = cvemap_json['cve_description']

    logging.info(f"Analyzing {cve}")
    doc_handler = DocHandler()

    analysis_start_time = time.time()
    result = doc_handler.vul_analysis(cve, output_dir, cve_description)
    analysis_end_time = time.time()
    searching_time = analysis_start_time - searching_start_time
    analysis_time = analysis_end_time - analysis_start_time
    logging.info(f"Analysis time: {analysis_time} seconds")
    
    with open(f"{output_dir}/{cve}/features.json", 'w') as f:
        
        json.dump(result, f, indent=4)

    return searching_time, analysis_time

def general_analysis(keyword, output_dir="resources/"):
    searching_start_time = time.time()
    compose(output_dir, keyword, loose_mode = True)

    cve = keyword

    cve_description = ""

    logging.info(f"Analyzing {keyword}")
    doc_handler = DocHandler()

    analysis_start_time = time.time()
    result = doc_handler.vul_analysis(cve, output_dir, cve_description)
    analysis_end_time = time.time()
    searching_time = analysis_start_time - searching_start_time
    analysis_time = analysis_end_time - analysis_start_time
    logging.info(f"Analysis time: {analysis_time} seconds")
    
    with open(f"{output_dir}/features.json", 'w') as f:
        
        json.dump(result, f, indent=4)

    return searching_time, analysis_time

def cve_analysis_from_epss_csv(csv_path):
    
    df = pd.read_csv(csv_path)
    # print(df.cve)
    with tqdm(total=len(df.index), desc=f'Analyzing CVEs') as pbar:
        for index, row in df.iterrows():
            cve = row['cve']
            if int(cve.split('-')[1]) < 2017 or int(cve.split('-')[1]) > 2022:
                logger.info(f"Skipping {cve}")
                pbar.update()
                continue
            try:
                cve_analysis(cve)
                time.sleep(1)
                pbar.update()
                logging.info(f"Finished {index}: {cve}")
            except Exception as e:
                logging.error(f"Error in {cve}: {e}")
                pbar.update()
                continue

def product_to_cve(product, output_dir):
    cve_lst = []
    product_dir_name = product.lower().replace(" ", "_").replace("/", "_").replace(":", "_").replace("\\", "_").replace("(", "_").replace(")", "_").replace('"', "").replace("'", "").replace("\n", "").replace("&", "")
    if os.path.exists(f"{output_dir}/{product_dir_name}"):
        with open(f"{output_dir}/{product_dir_name}/cve_lst.json") as f:
            cve_lst = json.load(f)
        return cve_lst

    os.makedirs(f"{output_dir}/{product_dir_name}", exist_ok=True)
    cleaned_product = product_keyword_gen_openai(product, 3)
    # print(cleaned_product)
    cleaned_product.append(product_dir_name)
    
    for p in cleaned_product:
    
        p_dir_name = p.lower().replace(" ", "_").replace("/", "_").replace(":", "_").replace("\\", "_").replace("(", "_").replace(")", "_").replace('"', "").replace("'", "").replace("\n", "").replace("&", "")
        cvemap_json_path = f"{output_dir}/{product_dir_name}/cvemap_{p_dir_name}.json"
        cvemap_command = f"cvemap -p '{p}' -j > {cvemap_json_path}"
        shell_result = subprocess.run(cvemap_command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=50)
        with open(cvemap_json_path) as f:
            json_data = json.load(f)
            for cve in json_data:
                cve_lst.append(cve['cve_id'])
            # print(json_data)
        
        with open(f"{output_dir}/{product_dir_name}/cve_lst.json", 'w') as f:
            json.dump(cve_lst, f, indent=4)
    
    return cve_lst

def product_keyword_gen_openai(product, num):
    prompt = (
        "You're an excellent system administrator. You will be given a product name, which may not be in a standard format. "
        "Your task is to generate alternative product names to broaden the search scope.\n"
        f"The given product name is {product}, please generate at most {num} alternative product names in the following format.\n"
        "[Alternative product name 1, Alternative product name 2, Alternative product name 3, ...]"
    )
    try:
        model_name = planning_config['model']
        llm = get_model(model_name)
        from langchain_core.messages import HumanMessage
        response = llm.invoke([HumanMessage(content=prompt)])
        product_lst_str = response.content.strip() if hasattr(response, 'content') else str(response)
    except Exception as e:
        import openai
        client = openai.OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": prompt},
            ],
        )
        product_lst_str = str(response.choices[0].message.content)
    product_lst = product_lst_str.strip("[]").replace("'", "").split(", ")
    # print(product_lst)
    product_lst = [product.lower().replace(" ", "_").replace("/", "_").replace(":", "_").replace("\\", "_").replace("(", "_").replace(")", "_").replace('"', "").replace("'", "").replace("\n", "").replace("&", "") for product in product_lst]

    return product_lst

def product_keyword_gen_huggingface(product, num):

    messages = [
        {"role": "system", "content": "You're an excellent system administrator. You will be given a product name, which may not be in a standard format. Your task is to generate alternative product names to broaden the search scope."},
        {"role": "user", "content": f"The given product name is {product}, please generate {num} alternative product names in the following format: [Alternative product name 1, Alternative product name 2, Alternative product name 3, ...]"},
    ]

    # Run with Local LLM
    product_lst = chat_completion_huggingface(
        model_name="meta-llama/Meta-Llama-3.1-8B-Instruct",
        messages=messages,
        max_tokens=200,
        temperature=0.0
    )

    return product_lst

def chat_completion_huggingface(model_name="meta-llama/Meta-Llama-3.1-8B-Instruct", messages=None, max_tokens=100, temperature=0.0, top_p=0.0):
    """
    Generates a chat completion using a specified Hugging Face model.

    Args:
        model_name (str): The Hugging Face model name (default is Mistral-7B-Instruct).
        messages (list): A list of chat messages in OpenAI format [{"role": "user", "content": "Hello"}].
        max_tokens (int): Maximum number of tokens to generate.
        temperature (float): Sampling temperature (higher = more creative, lower = more deterministic).
        top_p (float): Nucleus sampling parameter (controls randomness).

    Returns:
        str: The model's response.
    """

    # Load the model and tokenizer dynamically
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForCausalLM.from_pretrained(model_name, device_map="auto")  # Uses GPU if available

    # Convert messages into a formatted prompt
    prompt = ""
    for message in messages:
        if message["role"] == "system":
            prompt += f"<s>[SYSTEM]: {message['content']}\n"
        elif message["role"] == "user":
            prompt += f"[USER]: {message['content']}\n"
        elif message["role"] == "assistant":
            prompt += f"[ASSISTANT]: {message['content']}\n"
    prompt += "[ASSISTANT]:"

    # Tokenize input
    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)

    # Generate response
    output = model.generate(
        **inputs,
        max_new_tokens=max_tokens,
        temperature=temperature,
        top_p=top_p,
        do_sample=False
    )

    # Decode and return response
    response = tokenizer.decode(output[0], skip_special_tokens=True)
    return response.split("[ASSISTANT]:")[-1].strip()

def analyze_cve_lst(cve_lst, output_dir, app_name):
    cvss_results = {}
    cvss_scores = {}
    epss_results = {}
    epss_scores = {}
    pentestasst_results = {}
    pentestasst_scores = {}
    analysis_time_dict = {}
    has_code_lst = []
    total_searching_time = 0
    total_analysis_time = 0

    for cve in cve_lst:
        logging.info(f"Analyzing {cve}")
        if not os.path.exists(f"{output_dir}/{cve}/features.json"):
            searching_time, analysis_time = cve_analysis(cve, output_dir)
            if analysis_time == 0:
                continue
            total_searching_time += searching_time
            total_analysis_time += analysis_time
            analysis_time_dict[cve] = analysis_time
        cvss_score, cvss_category, epss_score, epss_category, final_score, exploitability, has_code = cve_classifier(cve, output_dir, mode = "specific")
        cvss_results[cve] = cvss_category
        cvss_scores[cve] = cvss_score
        epss_results[cve] = epss_category
        epss_scores[cve] = epss_score
        pentestasst_results[cve] = exploitability
        pentestasst_scores[cve] = final_score
        if has_code:
            has_code_lst.append(cve)

    with open(f"{output_dir}/analysis_time.json", 'w') as f:
        json.dump(analysis_time_dict, f, indent=4)

    # bin_df = create_df(cvss_results, epss_results, pentestasst_results)
    num_df = create_df(cvss_scores, epss_scores, pentestasst_scores)
    normalized_num_df = normalize_data(num_df)
    normalized_has_code_num_df = normalized_num_df.loc[has_code_lst]
    num_df.to_csv(f'{output_dir}/score_results.csv')
    normalized_num_df.to_csv(f'{output_dir}/normalized_score_results.csv')
    normalized_has_code_num_df.to_csv(f'{output_dir}/normalized_has_code_score_results.csv')


    if app_name:
        logging.info(f"Searching for general exp info for {app_name}")
        print("Start searching general exp info...")
        app_exp_path = app_name + "_exp"
        if not os.path.exists(f"{output_dir}/{app_exp_path}/features.json"):
            keyword = app_name + " exploit"
            searching_time, analysis_time = general_analysis(keyword, os.path.join(output_dir, app_exp_path))
            total_searching_time += searching_time
            total_analysis_time += analysis_time
        cve_classifier(app_exp_path, output_dir, mode = "general")

    avg_searching_time = total_searching_time / ((len(cve_lst) +1) if app_name else (len(cve_lst)))
    avg_analysis_time = total_analysis_time / ((len(cve_lst) +1) if app_name else (len(cve_lst)))
    logging.info(f"Total searching time: {total_searching_time} seconds, average time: {avg_searching_time} seconds")
    logging.info(f"Total analysis time: {total_analysis_time} seconds, average time: {avg_analysis_time} seconds")

    return total_searching_time, total_analysis_time


def get_exp_info(cve_lst = [], output_dir = "", app_name = ""):
    logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        filename='cve_info.log',
                        level=logging.INFO)
    
    track_tokens = False
    token_counter = None
    model_name = planning_config['model']
    if track_tokens:
        try:
            token_counter = TokenCountingHandler(tokenizer=tiktoken.encoding_for_model(model_name).encode)
            Settings.callback_manager = CallbackManager([token_counter])
        except Exception as e:
            logger.warning(f"Tokenizer for model {model_name} not found, token counting disabled: {e}")
            Settings.callback_manager = CallbackManager([])
    
    ### Step 1: Select the LLM

    ## Initialize LLM from config via model manager (provider-agnostic)
    try:
        model_name = planning_config['model']
    except Exception:
        model_name = "openai"

    llm = get_model(model_name)
    if llm is None:
        # Keep previous behavior when no API key/config: abort gracefully
        print("LLM_API_KEY not set")
        return

    try:
        Settings.llm = LangChainLLM(llm=llm)
    except Exception:
        # Fallback to OpenAI config if available to preserve behavior
        cve_config = config['cve']
        print(f"Model: {cve_config['model']}")
        Settings.llm = OpenAI(temperature=cve_config['temperature'], model=cve_config['model'])

    ### Step 2: Input the CVEs to analyze

    if not cve_lst:
        print("CVE to be searched not set! ")
        return
    

    ### Step 3: Analyze the CVEs
    if not output_dir:
        print("Directory to store not set! will use default settings.")
        output_dir = "resources_cve_lst_try"

    os.makedirs(output_dir, exist_ok=True)

    ## Scenario 2: Given a list of CVEs, analyze the CVEs

    total_searching_time, total_analysis_time = analyze_cve_lst(cve_lst, output_dir, app_name)


    if track_tokens:
        print(
            "Embedding Tokens: ",
            token_counter.total_embedding_token_count,
            "\n",
            "LLM Prompt Tokens: ",
            token_counter.prompt_llm_token_count,
            "\n",
            "LLM Completion Tokens: ",
            token_counter.completion_llm_token_count,
            "\n",
            "Total LLM Token Count: ",
            token_counter.total_llm_token_count,
            "\n",
            "Average LLM Token Count: ",
            token_counter.total_llm_token_count / len(cve_lst),
            "\n",
        )

        logging.info(
            "Embedding Tokens: "
            + str(token_counter.total_embedding_token_count)
            + "\n"
            + "LLM Prompt Tokens: "
            + str(token_counter.prompt_llm_token_count)
            + "\n"
            + "LLM Completion Tokens: "
            + str(token_counter.completion_llm_token_count)
            + "\n"
            + "Total LLM Token Count: "
            + str(token_counter.total_llm_token_count)
            + "\n"
            + "Average LLM Token Count: "
            + str(token_counter.total_llm_token_count / len(cve_lst))
            + "\n"
        )

        token_counter.reset_counts()

    return total_searching_time, total_analysis_time


def main():
    logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        filename='cve_info.log',
                        level=logging.INFO)
    
    track_tokens = False
    token_counter = None
    if track_tokens:
        token_counter = TokenCountingHandler(tokenizer=tiktoken.encoding_for_model("gpt-4o-mini").encode)
        Settings.callback_manager = CallbackManager([token_counter])
    
    ### Step 1: Select the LLM

    ## OpenAI API 
    api_key = os.environ.get("OPENAI_API_KEY")
    if api_key is None or api_key == "":
        print("OPENAI_API_KEY not set")
        return
    elif "f4Ph3uIoqGLC9" in api_key:
        print("Model: o3-mini")
        Settings.llm = OpenAI(temperature=0, model="o3-mini")
    elif "klO8n1OFxLWBoPIeDycM" in api_key:
        print("Model: gpt-4o-mini")
        Settings.llm = OpenAI(temperature=0, model="gpt-4o-mini")
    else:
        print("Model: gpt-4o-mini (default)")
        Settings.llm = OpenAI(temperature=0, model="gpt-4o-mini")
    # Settings.llm = OpenAI(temperature=0, model="o3-mini")

    ## Option 2: Read CVE list from file
    cve_lst = []
    with open("../../target_lst/vulhub_test/xstream.txt", 'r') as f:
        cve_lst = f.read().splitlines()

    ## Option 3: Hard-coded CVE list
    # cve_lst = ['CVE-XXX-XXXX', 'CVE-XXX-XXXX', 'CVE-XXX-XXXX', 'CVE-XXX-XXXX', 'CVE-XXX-XXXX']
    

    ### Step 3: Analyze the CVEs
    output_dir = "resources_test/xstream"
    os.makedirs(output_dir, exist_ok=True)

    ## Scenario 1: Given a list of CVEs, analyze the CVEs

    # analyze_cve_lst(cve_lst, output_dir)
    analyze_cve_lst(cve_lst, output_dir, "xstream")  # assume app's name is xstream


    if track_tokens:
        print(
            "Embedding Tokens: ",
            token_counter.total_embedding_token_count,
            "\n",
            "LLM Prompt Tokens: ",
            token_counter.prompt_llm_token_count,
            "\n",
            "LLM Completion Tokens: ",
            token_counter.completion_llm_token_count,
            "\n",
            "Total LLM Token Count: ",
            token_counter.total_llm_token_count,
            "\n",
            "Average LLM Token Count: ",
            token_counter.total_llm_token_count / len(cve_lst),
            "\n",
        )

        logging.info(
            "Embedding Tokens: "
            + str(token_counter.total_embedding_token_count)
            + "\n"
            + "LLM Prompt Tokens: "
            + str(token_counter.prompt_llm_token_count)
            + "\n"
            + "LLM Completion Tokens: "
            + str(token_counter.completion_llm_token_count)
            + "\n"
            + "Total LLM Token Count: "
            + str(token_counter.total_llm_token_count)
            + "\n"
            + "Average LLM Token Count: "
            + str(token_counter.total_llm_token_count / len(cve_lst))
            + "\n"
        )

        token_counter.reset_counts()
    

    # epss_csv_path = 'epss_scores-2024-08-06.csv'
    # cve_analysis_from_epss_csv(epss_csv_path)

 

if __name__ == "__main__":
    main()

