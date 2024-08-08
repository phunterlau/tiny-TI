import os
import json
import requests
from openai import OpenAI

def load_blog_content(url):
    reader_api_prefix = "https://r.jina.ai/"
    full_url = f"{reader_api_prefix}{url}"
    response = requests.get(full_url)
    return response.text

def parse_content_with_gpt(content):
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    
    prompt = f"""
    You are a helpful AI assistant for a cybersecurity analyst.
    Parse the following security threat intelligence blog content and return a JSON object representing a knowledge graph with the following information:
    1. Entities of indicator of compromise (IoC):
       - A list of file hashes (MD5, SHA, or SHA256) for key "file_hashes"
       - A list of file paths or file names for key "file_names"
       - A list of URLs, domains, or IPs used in the act for key 'url_ip'. the content may [.] or hxxp to hide . or http in malicious URLs, please replace them with . or http.
    2. Security events as a list of relations:
       - Threat actor name
       - Main methods
       - Steps in security kill chains and related IoCs for each step for "kill_chain_steps" (e.g. Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command and Control, Actions on Objectives)
       - file name to file hash mapping for "file_name_hash_mapping"
       - URL or IP vs payload file hash mapping for "url_ip_payload_mapping"
       - executable files and command calling logic (e.g. X executes Y in kill chain step Z) for "executable_files_calling_logic"
       - other IoCs interact (file calling or communication to another file or URL) for "other_IoCs_interact"
    3. Reference links of reports or blogs from other security vendors

    Example JSON output:

    {{
        "knowledge_graph": {{
            "IoCs": {{
            "file_hashes": [
                "
            ],
            "file_names": [
                "IMG-387470302099.jpg.exe",
                "WindowsCodecs.dll",
                "zqtxmo.bat"
            ],
            "url_ip": [
                "https://example.com/hash/path",
                "http://example.com/another/path"
            ]
            }},
            "security_events": {{
            "threat_actor": "Fancy Bear",
            "main_methods": [
                "Phishing",
                "Malware distribution"
            ],
            "kill_chain_steps": [
                {{
                "step": "Delivery",
                "related_IoCs": [
                    "hash1",
                    "hash2"]
                }},
                {{
                "step": "Exploitation",
                "related_IoCs": [
                    "hash3",
                    "hash4"]
                }},
            ],
            "file_name_hash_mapping": {{
                "a.exe": "hash4",
                "b.dll": "hash3",
                "z.sh": "hash5"
            }},
            "url_ip_payload_mapping": {{
                "url1": "hash1",
                "url5": "hash2"
            }},
            "executable_files_calling_logic": {{
                "b.exe": {{
                "executes": "c.dll",
                "step": "Execution"
                }}
            }},
            "other_IoCs_interact": [
                {{
                "file": "b.dll",
                "interacts_with": "z.bat"
                }}
            ]
            }},
            "reference_links": [
            "https://example.com/report1",
            "https://example.com/report2"
            ]
        }}
    }}

    Blog content:
    {content}
    """

    response = client.chat.completions.create(
        model="gpt-4o-mini",  # Using GPT-4 Turbo with JSON mode
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
        max_tokens=16000,
        response_format={"type": "json_object"}
    )

    return json.loads(response.choices[0].message.content)

def main(blog_url, output_file):
    content = load_blog_content(blog_url)
    parsed_data = parse_content_with_gpt(content)
    
    with open(output_file, "w") as f:
        json.dump(parsed_data, f, indent=2)
    
    print(f"Threat intelligence knowledge graph has been saved to '{output_file}'")

if __name__ == "__main__":
    blog_url = "https://unit42.paloaltonetworks.com/fighting-ursa-car-for-sale-phishing-lure/"
    main(blog_url, "threat_intel_knowledge_graph.json")