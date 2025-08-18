import os
import re

def result_matches_cve(query, result):
    """
    Given a query and a result string, this function checks if the result matches the CVE from the query.
    
    Steps:
      1. Check if the query contains a CVE identifier.
         - If not, return True (no filtering is required).
      2. Extract candidate CVE strings from the result (allowing hyphen or underscore).
      3. If no candidate is found in the result, return True.
      4. Otherwise, ensure that at least one candidate exactly matches the query CVE.
         - "Exact match" means that hyphen and underscore are equivalent and no extra digit follows.
    
    Returns True if either the query contains no CVE or if at least one candidate in the result matches the query CVE.
    Otherwise, returns False.
    """
    # Step 1: Check if the query contains a CVE.
    query_match = re.search(r'cve[-_ ]\d{4}[-_ ]\d+', query, re.IGNORECASE)
    if not query_match:
        # No CVE in query; no filtering needed.
        return True

    # Extract the CVE from the query.
    query_cve = query_match.group(0)

    # Decode result if it is a bytes object.
    if isinstance(result, bytes):
        result = result.decode('utf-8', errors='replace')
    
    # Step 2: Extract candidate CVE strings from the result.
    candidate_pattern = re.compile(r'cve[-_ ]\d{4}[-_ ]\d+', re.IGNORECASE)
    candidates = candidate_pattern.findall(result)
    
    # Step 3: If there are no candidate CVEs in the result, return True.
    if not candidates:
        return True

    # Step 4: Build a regex pattern from the query CVE.
    # Escape the query CVE for safe use in regex.
    escaped_query = re.escape(query_cve)
    # Replace the escaped hyphen with a character class to allow hyphen or underscore.
    flexible_query = escaped_query.replace(r'\-', r'[-_]')
    # Append a negative lookahead to ensure no extra digit immediately follows.
    pattern_str = flexible_query + r'(?!\d)'
    pattern = re.compile(pattern_str, re.IGNORECASE)
    
    # Return True if at least one candidate in the result exactly matches the query CVE.
    return bool(pattern.search(result))
    
def remove_empty_directories(contents):
    if os.path.isdir(contents):
        for i in os.listdir(contents):
            # recursive directory needs to be constantly updated
            remove_empty_directories(os.path.join(contents, i))
    # if rmdir get a nonempty dir, throw an exception
    try:
        if not os.listdir(contents):
            # remove
            os.rmdir(contents)
    except Exception as e:
        pass

def count_files_and_size(directory):
    total_size = 0
    file_count = 0

    for root, dirs, files in os.walk(directory):
        # skip .git dir
        if '.git' in dirs:
            dirs.remove('.git')
        
        for file in files:
            file_path = os.path.join(root, file)
            if os.path.isfile(file_path):  # make sure is file
                total_size += os.path.getsize(file_path)
                file_count += 1

    return file_count, total_size # total_size is for improvement

def remove_files(directory, filter_list, remove_no_extension=False):
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_extension = os.path.splitext(file)[1]
            # check if extension is in the list, or if not have extention and remove_no_extensionis True
            for i in range(len(filter_list)):
                if file_extension.lower() in filter_list[i]:
                    os.remove(file_path)
            if remove_no_extension and file_extension == '':
                os.remove(file_path)
