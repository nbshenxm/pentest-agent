import os
import re
import dotenv
from llama_index.readers.web import SimpleWebPageReader
from deep_translator import GoogleTranslator
from tqdm import tqdm
import spacy

dotenv.load_dotenv()

nlp = spacy.load("en_core_web_sm")

class AVDSearcher:
    ''' Searches for exploits on Alibaba Cloud Vulnerability Library and downloads them '''
    
    def __init__(self) -> None:
        pass

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

    def web_crawler(self, query, output_dir):
        ''' Crawl the AVD website to get the latest vulnerabilities '''

        # 1. extract the number of pages
        keywords = query.replace(" ", "+")
        search_res = SimpleWebPageReader(html_to_text=True).load_data([f"https://avd.aliyun.com/search?q={keywords}"])[0].text
        translated_search_res = self.translate_text(search_res)

        total_pages = 3
        match = re.search(r"Page 1 / (\d+)", translated_search_res)
        if match:
            total_pages = min(total_pages, int(match.group(1)))
        print(f"Total pages: {total_pages}")

        # 2. create a list of hyperlinks with details on the vulnerabilities
        hyperlinks = []
        for i in tqdm(range(1, total_pages + 1), desc="Crawling AVD pages"):
            page_url = f"https://avd.aliyun.com/search?q={keywords}&page={i}"
            avd_search_page = SimpleWebPageReader(html_to_text=True).load_data([page_url])[0].text
            translated_avd_search_page = self.translate_text(avd_search_page)
            # find all unique AVD-XXXX-XXXXX
            matches = list(set(re.findall(r"AVD-\d+-\d+", translated_avd_search_page)))
            for match in matches:
                # check if the match already exists as a directory in resources/AVD
                if os.path.exists(os.path.join(output_dir, match)):
                    continue
                hyperlink = f"https://avd.aliyun.com/detail?id={match}"
                hyperlinks.append((hyperlink, match))
        
        for (link, avd_id) in tqdm(hyperlinks, desc="Building KB"):
            try:
                self.build_readme(link, avd_id, output_dir)
            except:
                continue
    
    def build_readme(self, link, avd_id, output_dir):
        ''' Build a README file with the vulnerabilities found '''
        os.makedirs(os.path.join(output_dir, avd_id), exist_ok=True)
        document = SimpleWebPageReader(html_to_text=True).load_data([link])[0].text
        translated_document = self.translate_text(document)
        with open(os.path.join(output_dir, avd_id, "README.md"), 'w') as f:
            f.write(translated_document)

def main():
    a = AVDSearcher()
    keyword = "Jumpserver 3.0.0"
    app = "Jumpserver"
    # version = "3.0.0"
    a.web_crawler(app, f"resource/{keyword}/AVD")

if __name__ == "__main__":
    main()
