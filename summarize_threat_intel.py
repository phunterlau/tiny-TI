import json
import os
from openai import OpenAI

def generate_summary_and_questions(input_file, output_file):
    # Read the JSON data
    with open(input_file, 'r') as f:
        data = json.load(f)

    # Initialize OpenAI client
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

    # Prepare the prompt
    prompt = f"""
    You are a cybersecurity analyst assistant. Based on the following threat intelligence data, provide:
    1. A concise summary of the threat actor, their methods, and the observed attack chain.
    2. A list of 5 key questions for further investigation.

    Threat Intelligence Data:
    {json.dumps(data, indent=2)}

    Please format your response as a Markdown document with the following structure:
    # Threat Intelligence Summary

    ## Overview
    [Your summary here]

    ## Key Questions for Further Investigation
    1. [Question 1]
    2. [Question 2]
    3. [Question 3]
    4. [Question 4]
    5. [Question 5]

    ## IoCs
    - File Hashes: [List of file hashes]
    - URLs/IPs: [List of URLs and IPs]
    - File Names: [List of file names]

    ## VirusTotal Summary
    [Brief summary of VirusTotal results, including number of detections and any significant findings]
    """

    # Generate the summary and questions using GPT-4o-mini
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.7,
        max_tokens=1000
    )

    # Extract the generated content
    generated_content = response.choices[0].message.content

    # Write the generated content to the output file
    with open(output_file, 'w') as f:
        f.write(generated_content)

    print(f"Summary and questions have been saved to '{output_file}'")

if __name__ == "__main__":
    input_file = "threat_intel_with_virustotal.json"
    output_file = "threat_intel_summary.md"
    generate_summary_and_questions(input_file, output_file)