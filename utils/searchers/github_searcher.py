import os
import time
import json
import datetime
import dotenv
from tqdm import tqdm
import requests
from git import Repo
from urllib.parse import quote_plus
from utils.searchers.Domain_Filter import repository_filter, code_white_list
from utils.searchers.Extension_Filter import for_github_repo_file, for_github_code_file
from utils.searchers.util import *
import utils.searchers.github_config as c
from scipy.stats import norm
import csv
from datetime import datetime as dt
import shutil

dotenv.load_dotenv()

class GithubSearcher:
    search_limit_remaining = 30
    search_limit_reset = 0

    core_limit_remaining = 5000
    core_limit_reset = 0

    USE_PROXY = False
    proxies = {
        'http': 'socks5://127.0.0.1:50532',
        'https': 'socks5://127.0.0.1:50532'        
    }

    def __init__(self) -> None:
        self.session = requests.session()
        self.token = os.getenv('GITHUB_KEY')

    def convert_to_raw(self, github_blob_url):
        # replace "blob" with "raw" and return new RAW link
        github_raw_url = github_blob_url.replace("/github.com/", "/raw.githubusercontent.com/")
        if "blob/" in github_raw_url:
            github_raw_url = github_raw_url.replace("blob/", "")
        return github_raw_url

    def filter_items(self, items, keyword, size_limits, loose_mode = False):
        ###########################
        # filter nonrelative repo #
        ###########################
        related_items = []
        # print(items)
        for item in items:
            name_temp = str(item.get('name'))
            description_temp = str(item.get('description'))
            if 'cve' in keyword.lower():
                if result_matches_cve(keyword, name_temp) or result_matches_cve(keyword, description_temp):
                    related_items.append(item)

            if loose_mode:
                related_items.append(item)

        ########################
        # filter inferior repo #
        ########################
        # filter based on list content
        filtered_items = [item for item in related_items if not any(filter_string in item['html_url'] for filter_string in repository_filter)]
        # filter based on scoring
        extracted_items = []
        # traverse every item
        for item in filtered_items:
            # a new dict to store extracted data
            extracted_data = {}
            
            # extract html_url, empty -> skip this item
            html_url = item.get('html_url')
            if not html_url:
                continue
            
            # extract description
            description = item.get('description')
            if description is None:
                description_length = 0
            else:
                description_length = len(description)
            
            # extract open_issues_count; not exist or not valid -> try to extract open_issues
            open_issues_count = item.get('open_issues_count')
            if open_issues_count is None or not isinstance(open_issues_count, int):
                open_issues = item.get('open_issues')
                if open_issues is not None and isinstance(open_issues, int):
                    open_issues_count = open_issues
                else:
                    open_issues_count = 0

            # extract stargazers_count; not exist or not valid -> try to extract watchers_count; not exist or not valid -> try to extract watchers
            # update in original item
            stars_count = item.get('stargazers_count')
            if stars_count is None or not isinstance(stars_count, int):
                watchers_count = item.get('watchers_count')
                if watchers_count is not None and isinstance(watchers_count, int):
                    stars_count = watchers_count
                else:
                    watchers = item.get('watchers')
                    if watchers is not None and isinstance(watchers, int):
                        stars_count = watchers
                    else:
                        stars_count = 0
            item['stars_count'] = stars_count
            stars_count += 1 # to match up with fork calculation

            # extract forks_count; not exist or not valid -> try to extract forks
            # update in original item
            forks_count = item.get('forks_count')
            if forks_count is None or not isinstance(forks_count, int):
                forks = item.get('forks')
                if forks is not None and isinstance(forks, int):
                    forks_count = forks
                else:
                    forks_count = 0
            item['forks_count'] = forks_count
            forks_count += 1 # avoid using 0 as divisor

            # extract create_date; not exist or not valid -> set a default value
            create_date = item.get('created_at')
            if create_date is None or not isinstance(create_date, str):
                create_date = "2020-01-01T02:28:41Z"
            
            # extract topics; allow to be empty, and transfer it to a string splitted by comma
            topics_list = item.get('topics', [])
            topics_str = ','.join(topics_list)
            
            # add to new dict
            extracted_data['html_url'] = html_url
            extracted_data['description_length'] = description_length
            extracted_data['open_issues_count'] = open_issues_count
            extracted_data['topics'] = topics_str.lower()
            extracted_data['stars_count'] = stars_count
            extracted_data['forks_count'] = forks_count
            extracted_data['create_date'] = create_date
            
            extracted_items.append(extracted_data)

        for item in extracted_items:
            if item['description_length'] <= 300:
                d_score = c.max_confs[0]
            else:
                d_score = c.times_0 * norm.pdf(item['description_length'], loc=c.mus[0], scale=c.sigmas[0])

            if item['open_issues_count'] <= 30:
                i_score = c.max_confs[1]
            else:
                i_score = c.times_1 * norm.pdf(item['open_issues_count'], loc=c.mus[1], scale=c.sigmas[1])

            if keyword.strip().lower() in item['topics']:
                t_score = c.max_confs[2]
            else:
                t_score = 0.2 # avoid having a score difference that is too large, as it loses its meaning

            item['conf_score'] = d_score * c.conf_score_weights[0] + i_score * c.conf_score_weights[1] + t_score * c.conf_score_weights[2]
            

            # transfer to datetime object
            given_time = dt.fromisoformat(item['create_date'].replace("Z", ""))
            current_time = dt.now()
            # get the difference in days
            days_difference = (current_time - given_time).days
            lamda = c.times_2 * norm.pdf(days_difference, loc=c.mus[2], scale=c.sigmas[2]) + c.base_line
            item['efct_score'] = lamda * item['stars_count'] / item['forks_count']


        filtered_extracted_items = [item for item in extracted_items if item['conf_score'] >= c.threshold]

        effective_count = len(filtered_extracted_items)

        #####################
        # filter giant repo #
        #####################
        size_filtered_items = [item for item in filtered_items if item['size'] <= c.size_limits[2]]

        #############
        # sort repo #
        #############
        # sort in descending order based on efct_score
        sorted_filtered_extracted_items = sorted(filtered_extracted_items, key=lambda x: x['efct_score'], reverse=True)
        # merge results
        html_index = [item['html_url'] for item in sorted_filtered_extracted_items]
        merged_filtered_items = []
        for url in html_index:
            for item in size_filtered_items:
                if item['html_url'] == url:
                    merged_filtered_items.append(item)

        # grouping
        group1 = [item for item in merged_filtered_items if c.size_limits[0] <= item['size'] <= c.size_limits[1]]
        group2 = [item for item in merged_filtered_items if item['size'] < c.size_limits[0]]
        group3 = [item for item in merged_filtered_items if item['size'] > c.size_limits[1]]

        # merge groups
        grouped_filtered_items = []
        for item in group1:
            grouped_filtered_items.append(item)
        for item in group2:
            grouped_filtered_items.append(item)
        for item in group3:
            grouped_filtered_items.append(item)

        return grouped_filtered_items, effective_count

    def _search_code(self, query_type: str = 'repositories',
                          query_body: str = '',
                          qualifiers = '',
                          page: int = 1,
                          per_page: int = 30,
                          sort_method: str = '',
                          url=None,
                          keyword: str = '', size_limits: int = [0, 1000000],
                          loose_mode: bool = False ):
        timestamp = int(datetime.datetime.now().timestamp())
        # print("called!")
        if self.search_limit_remaining == 0 and timestamp < self.search_limit_reset + 3:
            time.sleep(self.search_limit_reset - timestamp + 5)

        if url is None:
            # URL encode the query_body
            query_body_encoded = quote_plus(query_body)
            query_body_encoded = quote_plus(query_body).rstrip('+')
            if loose_mode: # to get broader match result
                query_body_encoded = query_body.replace(' ', '+')
                query_body_encoded = query_body_encoded.replace('"', '')
            # construct the URL, ensuring that the parameters are separated by &, and check if the parameters exist.
            url = f'https://api.github.com/search/{query_type}?q={query_body_encoded}'
            if qualifiers:
                qualifiers_body_encoded = quote_plus(qualifiers)
                qualifiers_body_encoded = qualifiers_body_encoded.replace('+', '&')
                url += f'&{qualifiers_body_encoded}'
            if sort_method:
                url += f'&sort={sort_method}&order=desc'
            if page > 1:
                url += f'&page={page}'
            if per_page > 0:
                url += f'&per_page={per_page}'
            # print(url)

        header = {
            'Accept': 'application/vnd.github+json',
            'Authorization': f'Bearer {self.token}',
            'X-GitHub-Api-Version': '2022-11-28'
        }

        if self.USE_PROXY:
            resp = self.session.get(url, headers=header, proxies=self.proxies)
        else:
            resp = self.session.get(url, headers=header)
        next_page = None
        # print(resp.text)

        if 'link' in resp.headers.keys():
            links = resp.headers['link']
            links = links.split(',')
            for link in links:
                addr, rel = link.split(';')
                addr = addr.strip()[1:-1]

                if rel.find('next') >= 0:
                    next_page = addr

        if 'X-RateLimit-Remaining' in resp.headers.keys():
            self.search_limit_remaining = int(
                resp.headers['X-RateLimit-Remaining'])

        if 'X-RateLimit-Reset' in resp.headers.keys():
            self.search_limit_reset = int(resp.headers['X-RateLimit-Reset'])

        if 'Retry-After' in resp.headers.keys():
            after = int(resp.headers['Retry-After'])
            time.sleep(after + 3)

        if resp.status_code != 200:
            # print(resp.text)
            return None, None

        result = json.loads(resp.text)
        items = result.get('items', [])

        mode = True if loose_mode else False
        if query_type == 'repositories':
            filtered_items, effective_count = self.filter_items(items, keyword, size_limits, loose_mode = mode)
             # update result
            result['effective_count'] = effective_count
        elif query_type == 'code':
            filtered_items = [item for item in items if any(repo in item['html_url'] for repo in code_white_list)]
             # update result
            result['effective_count'] = len(filtered_items)
        # update result
        result['items'] = filtered_items
        
        return result, next_page

    def search_keyword(self, keyword:str, output_dir: str, filter_on: bool = True, loose_mode: bool = False):
        # print("github called")
        os.makedirs(output_dir, exist_ok=True)
        code_result = None

        mode = True if loose_mode else False
        repo_result, _ = self._search_code(query_type='repositories',
                                query_body=f'"{keyword}"',
                                qualifiers='',
                                per_page=c.per_page,
                                size_limits=c.size_limits, keyword = keyword, loose_mode = mode)
        if filter_on:
            code_result, _ = self._search_code(query_type='code',
                                    query_body=f'"{keyword}"',
                                    qualifiers='',
                                    keyword = keyword, loose_mode = mode)
        # print(repo_result)
        # with open ("test.txt", 'w') as f:
        #     f.write(json.dumps(repo_result, indent=4, ensure_ascii=False))
        #     f.write(json.dumps(code_result, indent=4, ensure_ascii=False))
        total_repo = 0
        total_code = 0
        if repo_result is None:
            print("search repo error")
        else:
            total_repo = repo_result['effective_count']

        if code_result is None:
            print("search code error")
        else:
            total_code = code_result['effective_count']

        # Maximum files available on Github
        repo_target_count = min(c.count_each_keyword, total_repo)
        code_target_count = min(c.count_each_keyword, total_code)

        repo_count = 0 
        # Repo Download Iteration
        with tqdm(total=repo_target_count, desc=f'Searching repositories related to {keyword} from GitHub') as pbar:
            try:
                for item in repo_result['items']:
                    repo_name = item['name']
                    # repo_full_name = item['full_name']
                    repo_language = item['language']
                    repo_star = item['stars_count']
                    repo_url = item['clone_url']

                    repo_directory = os.path.join(output_dir,
                                                f'{repo_star}_{repo_name}_{repo_language}')
                    if not os.path.exists(repo_directory):
                        os.mkdir(repo_directory)
                        Repo.clone_from(repo_url, repo_directory)
                        if filter_on:
                            file_count_0, _ = count_files_and_size(repo_directory)
                            # filter files, turn off when running pentestagent
                            remove_files(repo_directory, filter_list=for_github_repo_file, remove_no_extension=True)
                            file_count_1, _ = count_files_and_size(repo_directory)
                            if file_count_0 * 0.5 > file_count_1 or file_count_1 > c.file_num_limits:
                                shutil.rmtree(repo_directory)  # recursively remove directories
                            else:
                                repo_count += 1
                            if repo_count == c.base_limit:
                                break


                    pbar.update()

            except Exception as e:
                print(e)

        try:
            repo_result.pop('incomplete_results', None)
            for item in repo_result['items']:
                item.update({key: item[key] for key in ['name', 'clone_url', 'stars_count', 'forks_count'] if key in item})
                for key in list(item.keys()):
                    if key not in ['name', 'clone_url', 'stars_count', 'forks_count']:
                        del item[key]

            # repo_result['items'] = [{key: item[key] for key in item if key in ['name', 'clone_url', 'stars_count', 'forks_count']} for item in repo_result['items']]
            total_stars_count = 0 # initialize
            total_forks_count = 0 # initialize
            for item in repo_result['items']:
                total_stars_count += item['stars_count']
                total_forks_count += item['forks_count']
            repo_result['total_stars_count'] = total_stars_count
            repo_result['total_forks_count'] = total_forks_count
            if (repo_result['total_count'] <= c.per_page) or (repo_result['total_count'] > c.per_page and repo_result['effective_count'] < c.per_page):
                repo_result['trend_score'] = c.trend_weights[0] * repo_result['effective_count'] + c.trend_weights[1] * (total_stars_count + total_forks_count)
            else:
                repo_result['trend_score'] = c.trend_weights[0] * repo_result['total_count'] \
                                            + c.trend_weights[1] * (total_stars_count + total_forks_count) * c.alpha
            try:
                with open(os.path.join(os.path.dirname(output_dir), "Trend_Score.json"), "w") as f:
                    f.write(json.dumps(repo_result, indent=4, ensure_ascii=False))
            except Exception as e:
                print(e)

        except Exception as e:
            print(e)

        # Code Download Iteration
        code_output_dir = os.path.join(output_dir,"Code_File")
        if not os.path.exists(code_output_dir):
            os.makedirs(code_output_dir)
        index_csv_path = os.path.join(code_output_dir, 'index.csv')
        with tqdm(total=code_target_count, desc=f'Downloading code files related to {keyword} from GitHub') as pbar:
            # initialize index.csv
            with open(index_csv_path, 'w', newline='') as csvfile:
                fieldnames = ['original_path', 'original_name', 'new_name']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
            try:
                for item in code_result['items']:
                    file_name = item['name']
                    file_path = item['path']
                    file_url = self.convert_to_raw(item['html_url'])  # use html_url to download
                    suffix = file_name.split(".")[-1]

                    # selectively filter files
                    for i in range(len(for_github_code_file)):
                        if f".{suffix}" in for_github_code_file[i]:
                            continue

                    # generate nonrepeatable file name
                    unique_name = f"{dt.now().strftime('%Y%m%d%H%M%S%f')}.{suffix}"

                    # download file
                    response = requests.get(file_url)
                    if response.status_code == 200:
                        if not result_matches_cve(keyword, response.content):
                            continue
                        # save file content to local
                        with open(os.path.join(code_output_dir, unique_name), 'wb') as f:
                            f.write(response.content)
                        # update index.csv
                        with open(index_csv_path, 'a', newline='') as csvfile:
                            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                            writer.writerow({
                                'original_path': file_path,
                                'original_name': file_name,
                                'new_name': unique_name
                            })
                    else:
                        print(f"Failed to download {file_url}, status code: {response.status_code}")

                    pbar.update()

            except Exception as e:
                print(e)

            # check if index.csv only has headline
            with open(index_csv_path, 'r', newline='') as csvfile:
                reader = csv.reader(csvfile)
                rows = list(reader)  # extract all lines into a list

            if len(rows) == 1:
                os.remove(index_csv_path)
            
            print("Recursively removing empty directories...")
            remove_empty_directories(output_dir)


# def main():
#     g = GithubSearcher()
#     app = "CVE-2024-29847"
#     g.search_keyword(f"{app} exploit", "/root/try/exp_web_data")

# if __name__ == "__main__":
#     main()
