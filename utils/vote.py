import re
from utils.prompt import PentestAgentPrompt
import time

def split_result(text):
    sections = re.split(r'\[(.*?)\]', text)

    result = {}
    for i in range(1, len(sections), 2):
        section_name = sections[i].strip()
        section_content = sections[i + 1].strip()
        result[section_name] = section_content

    return result

def get_final_res(result, case_constraint = False):
    extracted_res = split_result(result)

    if case_constraint:
        final_res = "True" if "True" in extracted_res['Conclusion'] else "False"
    else:
        final_res = "True" if "true" in extracted_res['Conclusion'].lower() else "False"

    return str(final_res)

def judge(query_engine, query_string, voters, results, opinions, confidences, case_constraint = False):
    # "Here are the details of each voter:..."
    judge_query = PentestAgentPrompt.base_judge_query_1
    # judge_query = "The security assistants performed a scan based on the following instructions:" + \
    #     query_string + PentestAgentPrompt.base_judge_query_1
    for i in range(len(results)): # range(voters)
        # print("called")
        judge_query = judge_query + f"voter {i + 1}'s thought: {'True' if results[i] else 'False'}.\n" + f"His analysis is: {opinions[i]}\n\n\n"
    judge_query = judge_query + PentestAgentPrompt.base_judge_query_2
    # print(judge_query)
    result = str(query_engine.query(judge_query))
    # print(result)
    extracted_res = split_result(result)

    if case_constraint: # default case insensitive
        final_jdg = "True" if "True" in extracted_res['Final Judgment'] else "False"
    else:
        final_jdg = "True" if "true" in extracted_res['Final Judgment'].lower() else "False"

    return final_jdg


def vote(query_engine, query_string, vote_base = 1, no_vote = 3, opn_weight = 0.5, compulsory_multi = False, case_constraint = False, use_judge = False, dictatorship = True): # no_vote range is [0, 5]
    # if confidence score is low then vote
    voters = vote_base * 2 + 1
    results = []
    opinions = []
    confidences = []
    true_score = 0
    
    result = str(query_engine.query(query_string))
    # if query_string == PentestAgentPrompt.code_attack_probability_query:
    # print(result)
    extracted_res = split_result(result)

    if case_constraint:
        final_res = "True" if "True" in extracted_res['Conclusion'] else "False"
    else:
        final_res = "True" if "true" in extracted_res['Conclusion'].lower() else "False"

    if int(extracted_res['Confidence']) >= no_vote and not compulsory_multi: # do not compel single voters to vote
        return final_res
    
    else:
        results.append(True if final_res == "True" else False)

        if use_judge: # default not use judgement
            opinions.append(extracted_res['File Analysis'])

        confidences.append(extracted_res['Confidence']) # for future improvement

        for i in range(voters - 1):
            time.sleep(5) # avoid having similar results due to being processed in the same batch, maybe still too small based on current situation
            result = str(query_engine.query(query_string))
            # if query_string == PentestAgentPrompt.code_attack_probability_query:
            # print(result)
            extracted_res = split_result(result)

            if case_constraint: # default case insensitive
                final_res = True if "True" in extracted_res['Conclusion'] else False
            else:
                final_res = True if "true" in extracted_res['Conclusion'].lower() else False
            results.append(final_res)
        
            if use_judge: # default not use judgement
                opinions.append(extracted_res['File Analysis'])

            confidences.append(extracted_res['Confidence']) # for future improvement

        if use_judge and not (all(results) or not any(results)): # default not use judgement, even when voters get same result
        # if use_judge and (all(results) or not any(results)): # activate this in test to match condition more easily
        # if use_judge:
            judgement = judge(query_engine, query_string, voters, results, opinions, confidences)

            if dictatorship: # default use judger's opinion completely
                return judgement
            else:
                for i in range(voters):
                    if results[i]:
                        true_score += 1
                    else:
                        true_score -= 1
                true_score = opn_weight * (1 if judgement == "True" else -1) + \
                            (1 - opn_weight) * true_score + 0.00001 # add a small value to prevent it from being 0
                if true_score > 0:
                    return "True"
                else:
                    return "False"

        else:
            for i in range(voters):
                if results[i]:
                    true_score += 1
                else:
                    true_score -= 1
            
            if true_score + 0.00001 > 0: # add a small value to prevent it from being 0
                return "True"
            else:
                return "False"


    

def main():
    query_engine = "test"
    query_string = "test"
    print(vote(query_engine, query_string))

if __name__ == "__main__":
    main()