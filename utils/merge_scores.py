import os
import json

def process_classification_files(root_dir):
    # Used to store all scores data
    all_scores = []
    
    # Traverse the directory tree
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            if file == "classification.json":
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        scores = data.get('scores')
                        if scores is None or not isinstance(scores, list):
                            scores = []
                        
                        # Add file path information for each score item
                        for item in scores:
                            if len(item) >= 2:
                                abs_file_path = os.path.abspath(file_path)
                                classification_dir = os.path.dirname(abs_file_path)
                                
                                # search for files in the directory where the classification.json is located and its subdirectories
                                actual_file = None
                                for root, dirs, files in os.walk(classification_dir):
                                    if item[0] in dirs:
                                        actual_file = os.path.dirname(os.path.join(root, item[0]))
                                        break
                                
                                # if the file cannot be found, keep the original path
                                if actual_file is None:
                                    actual_file = abs_file_path
                                    
                                entry = {
                                    "file_path": actual_file,
                                    "name": item[0],
                                    "score": item[1]
                                }
                                all_scores.append(entry)
                except (json.JSONDecodeError, IOError) as e:
                    print(f"Error processing {file_path}: {e}")
    
    # Sort by score in descending order
    all_scores_sorted = sorted(all_scores, key=lambda x: x['score'], reverse=True)
    
    return all_scores_sorted

def save_to_plan_json(data, output_file):
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        print(f"Successfully saved results to {output_file}")
    except IOError as e:
        print(f"Error saving to {output_file}: {e}")

def merge(root_directory, output_json):
    # Process files
    results = process_classification_files(root_directory)
    
    # Save results
    save_to_plan_json(results, output_json)
    
    # Print some statistics
    print(f"Processed {len(results)} score entries in total")
    if results:
        print(f"Highest score: {results[0]['score']} ({results[0]['name']})")
        print(f"Lowest score: {results[-1]['score']} ({results[-1]['name']})")