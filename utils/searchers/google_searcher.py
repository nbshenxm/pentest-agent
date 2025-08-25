import os
from googlesearch import search
import re
from tqdm import tqdm
# import csv
from deep_translator import GoogleTranslator
import spacy
from bs4 import BeautifulSoup
import requests
from utils.searchers.Domain_Filter import domain_filter
from utils.searchers.Extension_Filter import for_google_webpage
from utils.searchers.util import *
from langdetect import detect
import time
from readability import Document
from inscriptis import get_text
import dotenv
from utils.model_manager import get_model

dotenv.load_dotenv()

nlp = spacy.load("en_core_web_sm")

class GoogleSearcher:
    '''Given a query with exploit name and app number, search on Google, get 10 hyperlinks, create folder with 10 different files from 10 links'''
    def __init__(self, model_name: str = "openai"):
        self.llm = get_model(model_name)

    def fetch_webpage_content(self,url, timeout=180):
        try:
            response = requests.get(url, timeout=timeout) # set timeout management
            response.raise_for_status()  # check if request is successful
            return response.text
        except requests.RequestException as e:
            print(f"Request Error: {e}")
            return None

    def translate_text(self, text, source='auto', target='en', max_length=5000):
        doc = nlp(text)
        parts = []
        current_part = ""
        
        for sent in doc.sents:
            if len(current_part) + len(sent.text) <= max_length:
                current_part += sent.text + " "
            else:
                parts.append(current_part)
                current_part = sent.text + " "
        if current_part:
            parts.append(current_part)
        
        translated_parts = [GoogleTranslator(source=source, target=target).translate(part.strip()) for part in parts if len(part.strip()) > 0]
        return ' '.join(translated_parts)
    
    def extract_content(self, result, start_marker, end_marker):
        # define regular expression pattern
        pattern = f'{start_marker}(.*?){end_marker}'
        # use re.DOTALL allows . to match any character, including newline characters
        matches = re.findall(pattern, result, re.DOTALL)
        return matches
    
    def filter_full_file(self, file_content):
        # use configed LLM to filter files
        if not self.llm:
            print("LLM not initialized, skipping file filtering")
            return "<<@#%_tag useless >>@#%_tag"
            
        from langchain_core.messages import HumanMessage, SystemMessage
        
        system_message = SystemMessage(content="""You're an excellent cybersecurity penetration tester assistant. 
        You need to help the tester in filtering a file's content, and your commitment is essential to the task. 
        You will be provided a file's content, you need to read it, and then use your knowledge to determine if the file is directly useful for an actual penetration.
        "DIRECTLY USEFUL" means you can directly follow the instructions provided by the file to penetrate.
        If so, you are supposed to label it, then it will be passed to your co-workers.

        To help you understand what is "DIRECTLY USEFUL", here are some examples: 
        \t\t"code(s):\n  <?php
                                // PHP script to test file upload vulnerability
                                echo "File upload vulnerability test successful";
                                ?>"
        \t\t"plain instruction(s):\n   Open the login page of the target website.
                                Enter the following code in the username or password field: <script>alert('XSS')</script>.
                                Submit the form.
                                If there is an XSS vulnerability, a warning box with the word "XSS" will pop up in your browser."
        \t\t"command line operation(s):\n  curl -d "username=whoami; cat /etc/passwd" http://example.com/login\n
                                                or\n
                                                netsh>rpc
                                                netsh rpc>filter
                                                netsh rpc filter>add rule layer=um actiontype=block
                                                netsh rpc filter>add condition field=if_uuid matchtype=equal data=4b324fc8-1670-01d3-1278-5a47bf6ee188
                                                netsh rpc filter>add filter
                                                netsh rpc filter>quit"
        \t\t"payload(s):\n   ' OR 1=1 --    "
         
        To make the progress more efficient, we need to predefine a pair of unique strings("<<@#%_tag", ">>@#%_tag") in your answer so that others will recognize them easier.
        So the format in your answer should looks like: "<<@#%_tag useful >>@#%_tag" or "<<@#%_tag useless >>@#%_tag". The tag should be unique.
        
        Remember, you should be careful. A common misleading scenario is a file actually contains something helpful, but it is too long or the information is hidden too deeply that can make it be excluded. So you need to carefully read the whole text. 
        Meanwhile, to reduce your co-workers' burdens, you need to be strict. It is okay that you find the file is not actually useful to execute penetration. If so, feel free to skip those parts.
        You do not need to make assumption that a strange URL or link may contain something useful. We can access them through other approaches. So if these things appear in the file, make sure they do not affect your judgement.
        You can summarize but do not conclude or make assumptions, and your answer should be your most confident one. Keep the answer concise.
        """)

        user_message = HumanMessage(content=f"""Please make judgement and filter the following content: \n\n{file_content}
        \n\n\n\n\n

        Please make sure that you have used the unique string pair("<<@#%_tag", ">>@#%_tag"), especially do not forget to add ">>@#%_tag" as an end.""")

        try:
            response = self.llm.invoke([system_message, user_message])
            summary = response.content.strip()
            return summary
        except Exception as e:
            print(f"Error calling LLM: {e}")
            return "<<@#%_tag useless >>@#%_tag"

    def search_keyword(self, keyword: str, output_dir: str):
        # print("google called")
        links = []
        search_keyword = keyword 
        # domain_filter = ["github", "suibian"]
        # + " exploit"
        search_results = []
        try:
            time.sleep(5)
            search_results = search(search_keyword, num_results=10)
        except:
            print("Error occurred during google search. Continuing...")

        search_results = list(search_results)[:10]

        # create list with all links
        for result in search_results:
            # print(result)
            if all(domain not in result.lower() for domain in domain_filter):
                web_name = result.split("//")[1]
                web_name = web_name.replace("/", "-")
                web_name = web_name[:30] if len(web_name) > 30 else web_name
                links.append((web_name, result))
        # if not os.path.exists(output_dir):
        self.create_directories(output_dir, links)
    
    def create_directories(self, output_dir, links):
        # create a folder if it doesn't exist already
        # print("called!")
        os.makedirs(output_dir, exist_ok=True)
        for (name, link) in tqdm(links, desc="Crawling Google pages"):
            try:
                # if exist, then skip
                if os.path.exists(os.path.join(output_dir, name)):
                    continue

                time.sleep(5)
                # document = SimpleWebPageReader(html_to_text=True).load_data([link])[0].text
                soup = BeautifulSoup(self.fetch_webpage_content(link), "html.parser")

                # extension list
                extensions_to_remove = for_google_webpage

                # remove images
                for ule_tag in soup.find_all('True'):
                    src = ule_tag.get('src')
                    if src and any(src.lower().endswith(ext) for ext in extensions_to_remove):
                        ule_tag.decompose()

                # remove links, may not necessary
                # for a_tag in soup.find_all('a'):
                #     href = a_tag.get('href')
                #     if href and any(href.lower().endswith(ext) for ext in extensions_to_remove):
                #         a_tag.decompose()

                doc = Document(soup.prettify()) # restore to html format, then transfer to the format can be processed by readability
                content = doc.summary() # summarize, remove nonrelated content, html format
                full_text = get_text(content) # get clean text, with relative location remained

                # not empty -> creaye directory, else skip
                if full_text.strip():
                    os.mkdir(os.path.join(output_dir, name))
                else:
                    continue

                # translate Chinese webpages 
                if full_text.strip():
                    lan = detect(full_text)
                    # print(language)
                    if lan != "en":
                        time.sleep(5)
                        full_doc = self.translate_text(full_text)
                    else:
                        full_doc = full_text

            except Exception as e:
                print("Error occurred while downloading web page:", e)
                continue

            if len(full_doc) > 1000000:
                continue
            
            # use LLM to filter, then create md doc 
            full_doc_judgement = self.filter_full_file(full_doc)
            # print(full_doc_judgement)
            full_doc_judgement = self.extract_content(full_doc_judgement, '<<@#%_tag', '>>@#%_tag')
            # print(full_doc_judgement)
            if full_doc_judgement[0].strip() == "useful":
                with open(os.path.join(output_dir, name, "R_DOC.md"), "w") as f:
                    f.write(f"link to this page is {link}\n\n")
                    f.write(full_doc)

        remove_empty_directories(output_dir)
        
            

            

# def main():
#     g = GoogleSearcher()
#     base_dir = "/root/crawl_classify/data/"
#     level = "WPNZ"
#     # with open(os.path.join(base_dir, "index", f"{level}.csv"), mode='r', newline='', encoding='utf-8') as file:
#     with open(os.path.join(base_dir, "index", "example1.csv"), mode='r', newline='', encoding='utf-8') as file:
#         reader = csv.reader(file, delimiter='\t')

#         for row in reader:
#             avd_id, cve_id, zh_keyword, avd_url = row
#             if cve_id != "N/A":
#                 g.search_keyword(f"{cve_id} exlpoit", os.path.join(base_dir, level, avd_id, "temp"))
#             time.sleep(30)

    

# if __name__ == "__main__":
#     main()

