import os 
import json 
import requests
import time
import sys
import subprocess
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from configs.recon_config import RECON_LIMIT
from utils.prompts import PentestAgentPrompt
import logging
logger = logging.getLogger(__name__)

class ReconAgent:
    ollama_url = "http://localhost:11434/api"  
    model_name = "qwen3:1.7b"  
    
    conversations = {}
    state = {}
    
    state_file_dir = os.environ.get("CHAT_THREAD_TOPIC_DIR", './resources/cache/chat_thread_topic.json')
    state_file_path = os.path.join(state_file_dir, "recon_agent_state.json")
    
    def __init__(self, model_name=None, ollama_url=None):
        if not os.path.exists(self.state_file_dir):
            os.makedirs(self.state_file_dir)
            
        if model_name:
            self.model_name = model_name
        if ollama_url:
            self.ollama_url = ollama_url
            
        self.load_state()
        if not self.state.get('model_name'):
            self.state['model_name'] = self.model_name
            self.save_state()
            
        print(f"Using Ollama with model: {self.model_name}")
    
    def extract_json_from_text(self, text):
        import re
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            json_pattern = r'({[\s\S]*})'
            matches = re.findall(json_pattern, text)
            
            for potential_json in matches:
                try:
                    return json.loads(potential_json)
                except json.JSONDecodeError:
                    continue

            text = text.replace("'", '"')
            text = re.sub(r'(\s*?{\s*?|\s*?,\s*?)(\w+)(\s*?):', r'\1"\2"\3:', text)
            
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return None
        
    def save_state(self):
        self.state['model_name'] = self.model_name
        self.state['conversations'] = self.conversations
        
        try:
            with open(self.state_file_path, 'w') as file:
                json.dump(self.state, file)
            print(f"State saved to {self.state_file_path}")
        except Exception as e:
            print(f"An error occurred while saving state: {e}")

    def load_state(self):
        try:
            with open(self.state_file_path, 'r') as file:
                self.state = json.load(file)
                if 'conversations' in self.state:
                    self.conversations = self.state['conversations']
                if 'model_name' in self.state:
                    self.model_name = self.state['model_name']
            print(f"State loaded from {self.state_file_path}")
        except FileNotFoundError:
            self.state = {}
            print(f"No state file found at {self.state_file_path}, starting with an empty state.")
        except json.JSONDecodeError:
            self.state = {}
            print(f"State file {self.state_file_path} is corrupted, starting with an empty state.")
        except Exception as e:
            self.state = {}
            print(f"An error occurred while loading state: {e}")

    def init_thread(self, topic):
        system_prompt = PentestAgentPrompt.recon_init + """
            IMPORTANT: You must always respond with valid JSON in the following format:
            {
                "thought": "Your analysis and reasoning about the reconnaissance task",
                "executable": "The shell command to execute, or 'None' if no command is needed",
                "explanation": "Explanation of what the command does or why no command is needed"
            }
            
            When given a target, whether it's an IP address or domain name, use appropriate reconnaissance 
            techniques for that target type. For domains, consider DNS enumeration, subdomain discovery, 
            and web application scanning. For IP addresses, focus on port scanning, service enumeration, 
            and vulnerability detection.
            
            Do not include any text outside the JSON structure. Do not use markdown formatting, code blocks 
            or any other formatting that would make the JSON invalid.
        """
        
        self.conversations[topic] = [
            {"role": "system", "content": system_prompt}
        ]
        self.save_state()

    def load_thread(self, topic, thread_id):
        try:
            with open(thread_id, 'r') as f:
                self.conversations[topic] = json.load(f)
        except Exception as e:
            print(f"Could not load thread from {thread_id}: {e}")
            self.init_thread(topic)

    def send_message(self, topic, msg_content):
        if topic not in self.conversations:
            self.init_thread(topic)
            
        self.conversations[topic].append({"role": "user", "content": msg_content})
        self.save_state()

    def get_last_message(self, topic):
        if topic in self.conversations and len(self.conversations[topic]) > 0:
            for msg in reversed(self.conversations[topic]):
                if msg["role"] == "assistant":
                    return msg["content"]
        return ""

    def list_messages(self, topic):
        if topic in self.conversations:
            for msg in self.conversations[topic]:
                if msg["role"] != "system":
                    print(f"{msg['role']}: {msg['content']}")
    
    def run_shell_command(self, command):
        try:
            result = subprocess.run(
                command, 
                shell=True, 
                check=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, text=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            return e.stderr

    def run_thread(self, topic):
        if topic not in self.conversations:
            print(f"No conversation found for topic {topic}")
            return None
            
        try:
            response = requests.post(
                f"{self.ollama_url}/chat", 
                json={
                    "model": self.model_name,
                    "messages": self.conversations[topic],
                    "stream": False,
                }
            )
            
            if response.status_code == 200:
                result = response.json()
                assistant_message = result.get("message", {})
                
                self.conversations[topic].append(assistant_message)
                self.save_state()
                
                return type('obj', (object,), {'status': 'completed'})
            else:
                print(f"Error from Ollama API: {response.text}")
                return type('obj', (object,), {'status': 'failed'})
                
        except Exception as e:
            print(f"Error calling Ollama API: {e}")
            return type('obj', (object,), {'status': 'failed'})
        

def main():
    log_path = os.path.join(os.environ.get("LOG_DIR", "logs"), "recon_agent.log")
    if not os.path.exists(os.environ.get("LOG_DIR", "logs")):
        os.makedirs(os.environ.get("LOG_DIR", "logs"))
    logging.basicConfig(filename=log_path, 
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)

    
    start_time = time.time()

    recon_agent = ReconAgent(model_name="qwen3:1.7b")  

    curr_topic = "ollama_testing"  
    
    target_type = "ip"  
    target = "44.228.249.3" 
    
    if target_type == "ip":
        recon_init_message = f"I want to exploit target host with IP: {target}"
    else:
        recon_init_message = f"I want to exploit target domain: {target}"
        
    logger.info(f"Starting reconnaissance on {curr_topic} for target {target} ({target_type}) \n\n")      
    recon_agent.init_thread(curr_topic)
    recon_agent.send_message(curr_topic, recon_init_message)
    
    iter_count = 0
    while iter_count < RECON_LIMIT:       
        res = recon_agent.run_thread(curr_topic)
        if res.status == 'completed':
            msg = recon_agent.get_last_message(curr_topic)
            print(msg)
            logger.info("recon. agent:\n"+msg+"\n\n")

            json_msg = recon_agent.extract_json_from_text(msg)
            if not json_msg:
                print("Extracted string is not a valid JSON")
                recon_agent.send_message(curr_topic, "The previous message is not in valid JSON format. Please return it in valid JSON format with these fields: thought, executable, explanation")
                continue
            
            cmd = json_msg['executable']
            if cmd != 'None':
                cmd_res = recon_agent.run_shell_command(cmd)
                print(cmd_res)
                logger.info("shell:\n"+cmd_res+"\n\n")
                recon_agent.send_message(curr_topic, "Here is what I got from executing previous executable command.\n" + cmd_res)    
            else:
                recon_agent.send_message(curr_topic, PentestAgentPrompt.recon_summary)
                break
            iter_count += 1
        else:
            print(res.status)
            break
    
    res = recon_agent.run_thread(curr_topic)
    if res.status == 'completed':
        msg = recon_agent.get_last_message(curr_topic)
        print(msg)
        logger.info("recon. summary:\n"+msg+"\n\n")
    else:
        print(res.status)

    end_time = time.time()
    execution_time = end_time - start_time
    logging.info(f"Planning agent execution started at {start_time:.6f} and ended at {end_time:.6f}. The execution time is {execution_time:.6f} seconds")

if __name__ == "__main__":
    main()