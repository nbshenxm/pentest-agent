from utils.searchers.google_searcher import *
from utils.searchers.github_searcher import *
from utils.searchers.exploitdb_searcher import *
import os

def compose(target_dir: str, keyword: str, s1 = GoogleSearcher(), s2 = GithubSearcher(), s3 = ExploitDBSearcher(), loose_mode: bool = False):
    if not loose_mode:
        target_dir = os.path.join(target_dir, keyword)
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)
    else:
        print(f"{target_dir} exists!")
        return

    info_srcs = ["Google", "GitHub", "ExploitDB"]
    for info_src in info_srcs:
        subfolder_path = os.path.join(target_dir, info_src)
        if not os.path.exists(subfolder_path):
            os.makedirs(subfolder_path)

    # print(f"Searching {keyword} exploit from {info_srcs[0]}:")
    # s1.search_keyword(f"{keyword} exploit", os.path.join(target_dir, info_srcs[0]))
    mode = True if loose_mode else False
    print(f"Searching {keyword} exploit from {info_srcs[1]}:")
    s2.search_keyword(f"{keyword}", os.path.join(target_dir, info_srcs[1]), loose_mode = mode)
    print(f"Searching {keyword} from {info_srcs[2]}:")
    s3.search_keyword_local(keyword, os.path.join(target_dir, info_srcs[2]), loose_mode = mode)
    
def main():
    target_dir = "/root/exp_web_data"
    keyword = "cve-2021-42013" # "exploit" will be automaticcaly added
    compose(target_dir, keyword)

if __name__ == "__main__":
    main()
