import os
import json
import argparse
from urllib.parse import urlparse
from ti_parser import main as parse_blog
from virustotal_lookup import process_hashes_from_json
from vis import generate_d3_visualization

def sanitize_filename(url):
    parsed_url = urlparse(url)
    return f"{parsed_url.netloc}{parsed_url.path}".replace("/", "_").replace(".", "_")

def run_workflow(url, use_cache=False):
    # Generate filenames
    base_filename = sanitize_filename(url)
    initial_json_filename = f"{base_filename}_initial.json"
    vt_json_filename = f"{base_filename}_with_vt.json"
    html_filename = f"{base_filename}_visualization.html"

    # Check if cache should be used
    if use_cache and os.path.exists(vt_json_filename):
        print(f"Using cached data from {vt_json_filename}")
    else:
        # Step 1: Parse the blog and generate initial JSON
        parse_blog(url, initial_json_filename)
        print(f"Blog parsed and saved to {initial_json_filename}")

        # Step 2: Process hashes with VirusTotal
        process_hashes_from_json(initial_json_filename, vt_json_filename)
        print(f"VirusTotal data processed and saved to {vt_json_filename}")

    # Step 3: Generate D3.js visualization
    generate_d3_visualization(vt_json_filename, html_filename)
    print(f"Visualization generated and saved to {html_filename}")

    print(f"\nWorkflow completed. Output files:")
    print(f"  Initial JSON: {initial_json_filename}")
    print(f"  JSON with VirusTotal data: {vt_json_filename}")
    print(f"  HTML Visualization: {html_filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process a security blog URL and generate threat intelligence visualizations.")
    parser.add_argument("url", help="The URL of the security blog to process")
    parser.add_argument("--use-cache", action="store_true", help="Use cached data if available")
    args = parser.parse_args()

    run_workflow(args.url, use_cache=args.use_cache)