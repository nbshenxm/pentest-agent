import os
from pathlib import Path

c1_ext = ['py', 'pyw', 'pyc', 'pyo', 
          'js', 'mjs', 'cjs', 
          'sh', 'bash', 'zsh', 
          'rb', 'gem', 
          'php', 
          'pl', 'pm', 
          'r', 
          'lua', 
          'jl', 
          'ps1', 'psm1']

c3_ext = ['sql', 
          'html', 'htm', 
          'css', 
          'xml', 'xsd', 'xsl', 
          'json', 
          'yaml', 'yml', 
          'http', 'rest', 
          'ini', 
          'tf', 'tfvars', 
          'j2', 'jinja', 'jinja2', 
          'md', 'markdown', 'csv', 
          'tex', 'sty', 'cls', 
          'cypher', 'cql']

def extract_extensions(path):
    extensions = []
    have_md = False

    # recursively search
    for root, dirs, files in os.walk(path):
        # skip directory strat with "."
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        
        for file in files:
            # 跳skip file start with "."
            if file.startswith('.'):
                continue
                
            file_path = Path(file)
            ext = file_path.suffix[1:] if file_path.suffix else ''

            if not ext:
                extensions.append('sh')
            elif ext.lower() == 'md':
                have_md = True
                continue
            else:
                extensions.append(ext.lower())

    if have_md and len(extensions) == 0:
        extensions.append('md')
    
    return extensions

def get_class(ext_list):
    is_c1 = True
    is_c3 = True
    for ext in ext_list:
        if ext in c1_ext:
            continue
        elif ext in c3_ext:
            is_c1 = False
            continue
        else:
            is_c1 = False
            is_c3 = False
            break

    if is_c1: return "c1"
    elif is_c3: return "c3"
    else: return "c2"

def judge_class(repo_dir):
    ext_list = extract_extensions(repo_dir)
    class_res = get_class(ext_list)
    return class_res