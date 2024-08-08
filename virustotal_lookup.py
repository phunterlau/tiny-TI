import os
import json
import requests
import time
from typing import List, Dict, Any

# Make sure to set your VirusTotal API key as an environment variable
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def lookup_hash_on_virustotal(file_hash: str) -> Dict[str, Any]:
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        
        # Extract relevant information
        result = {
            "hash": file_hash,
            "detection_ratio": f"{data['data']['attributes']['last_analysis_stats']['malicious']}/{data['data']['attributes']['last_analysis_results'].__len__()}",
            "first_submission_date": data['data']['attributes'].get('first_submission_date'),
            "last_analysis_date": data['data']['attributes'].get('last_analysis_date'),
            "detections": [],
            "comments": []
        }
        
        # Collect detections
        for engine, detection in data['data']['attributes']['last_analysis_results'].items():
            if detection['category'] == 'malicious':
                result['detections'].append({
                    "engine": engine,
                    "result": detection['result']
                })
        
        # Collect comments (if available)
        if 'comments' in data['data']['attributes']:
            for comment in data['data']['attributes']['comments']:
                result['comments'].append({
                    "date": comment['date'],
                    "text": comment['text']
                })
        
        return result
    else:
        return {"error": f"Failed to retrieve data for hash {file_hash}. Status code: {response.status_code}"}

def process_hashes_from_json(input_file: str, output_file: str):
    # Read the input JSON file
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    # Extract file hashes from the IoCs
    file_hashes = data.get('knowledge_graph', {}).get('IoCs', {}).get('file_hashes', [])
    
    # Look up each hash on VirusTotal
    virustotal_results = []
    for file_hash in file_hashes:
        result = lookup_hash_on_virustotal(file_hash)
        virustotal_results.append(result)
        print("Processed hash ", file_hash, " and slept for 15 seconds")
        time.sleep(15)  # Sleep for 15 seconds to respect VirusTotal's rate limit
    
    # Add VirusTotal results to the main JSON
    data['knowledge_graph']['virustotal_results'] = virustotal_results
    
    # Write the updated JSON to the output file
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)

if __name__ == "__main__":
    input_file = "threat_intel_knowledge_graph.json"
    output_file = "threat_intel_with_virustotal.json"
    process_hashes_from_json(input_file, output_file)
    print(f"Updated threat intelligence with VirusTotal data has been saved to '{output_file}'")