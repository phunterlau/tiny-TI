import json
from datetime import datetime

def generate_d3_visualization(input_file, output_file):
    # Read the JSON data
    with open(input_file, 'r') as f:
        data = json.load(f)

    # Extract relevant information
    knowledge_graph = data['knowledge_graph']
    iocs = knowledge_graph['IoCs']
    security_events = knowledge_graph['security_events']
    virustotal_results = knowledge_graph.get('virustotal_results', [])

    # Prepare nodes and links for D3.js
    nodes = []
    links = []
    node_ids = {}

    # Helper function to add a node
    def add_node(name, group, extra_info=None):
        if name not in node_ids:
            node_ids[name] = len(nodes)
            node_data = {"id": node_ids[name], "name": name, "group": group}
            if extra_info:
                node_data.update(extra_info)
            nodes.append(node_data)
        return node_ids[name]

    # Add threat actor
    threat_actor_id = add_node(security_events['threat_actor'], "Threat Actor")

    # Add kill chain steps and link to threat actor
    for step in security_events['kill_chain_steps']:
        step_id = add_node(step['step'], "Kill Chain Step")
        links.append({"source": threat_actor_id, "target": step_id, "type": "has kill chain"})

    # Add IoCs
    file_hashes = iocs['file_hashes']
    if isinstance(file_hashes, list):
        # If file_hashes is a list, process each hash directly
        for hash_value in file_hashes:
            add_node(hash_value, "IoC (File Hash)")
    elif isinstance(file_hashes, dict):
        # If file_hashes is a dictionary, process each list of hashes
        for hash_list in file_hashes.values():
            for hash_value in hash_list:
                add_node(hash_value, "IoC (File Hash)")

    # Process VirusTotal results
    for vt_result in virustotal_results:
        hash_value = vt_result['hash']
        if hash_value in node_ids:
            ioc_id = node_ids[hash_value]
            extra_info = {
                "detection_ratio": vt_result['detection_ratio'],
                "first_detection": datetime.utcfromtimestamp(vt_result['first_submission_date']).strftime('%Y-%m-%d'),
                "last_detection": datetime.utcfromtimestamp(vt_result['last_analysis_date']).strftime('%Y-%m-%d')
            }
            nodes[ioc_id].update(extra_info)

            # Add VirusTotal detection rate as an attribute node
            vt_id = add_node(f"VT: {vt_result['detection_ratio']}", "VirusTotal")
            links.append({"source": ioc_id, "target": vt_id, "type": "detection rate"})

    # Link IoCs to kill chain steps
    for step in security_events['kill_chain_steps']:
        step_id = node_ids[step['step']]
        for hash_value in step['related_IoCs']:
            if hash_value in node_ids:
                ioc_id = node_ids[hash_value]
                links.append({"source": step_id, "target": ioc_id, "type": "related"})

    # Add file names
    for file_name in iocs['file_names']:
        add_node(file_name, "IoC (File Name)")

    # Add URLs/IPs
    for url in iocs['url_ip']:
        add_node(url, "IoC (URL/IP)")

    # Add file hash mapping
    for file_name, hash_value in security_events['file_name_hash_mapping'].items():
        if file_name not in node_ids:
            add_node(file_name, "IoC (File Name)")
        if hash_value not in node_ids:
            add_node(hash_value, "IoC (File Hash)")
        file_id = node_ids[file_name]
        hash_id = node_ids[hash_value]
        links.append({"source": file_id, "target": hash_id, "type": "is hash of"})

    # Add URL/IP payload mapping
    for url, payload_hash in security_events['url_ip_payload_mapping'].items():
        if url not in node_ids:
            add_node(url, "IoC (URL/IP)")
        if payload_hash not in node_ids:
            add_node(payload_hash, "IoC (File Hash)")
        url_id = node_ids[url]
        payload_id = node_ids[payload_hash]
        links.append({"source": url_id, "target": payload_id, "type": "downloads"})

    # Add executable files calling logic
    for caller, info in security_events['executable_files_calling_logic'].items():
        caller_id = add_node(caller, "Executable")
        callee_id = add_node(info['executes'], "Executable")
        step_id = node_ids[info['step']]
        links.append({"source": caller_id, "target": callee_id, "type": "executes"})
        links.append({"source": step_id, "target": caller_id, "type": "involves"})

    # Add other IoCs interaction
    for interaction in security_events['other_IoCs_interact']:
        file_id = add_node(interaction['file'], "IoC (File Name)")
        interacts_id = add_node(interaction['interacts_with'], "IoC (File Name)")
        links.append({"source": file_id, "target": interacts_id, "type": "interacts with"})

    # Generate HTML with embedded D3.js visualization
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Security Event Knowledge Graph</title>
        <script src="https://d3js.org/d3.v5.min.js"></script>
        <style>
            body {{
                font-family: 'Courier New', monospace;
                background-color: #0a0a0a;
                color: #33ff33;
                margin: 0;
                padding: 0;
            }}
            svg {{
                background-color: #000000;
            }}
            .links line {{
                stroke: #ffffff;
                stroke-opacity: 0.6;
            }}
            .nodes circle {{
                stroke: #000000;
                stroke-width: 1.5px;
            }}
            .text {{
                fill: #33ff33;
                font-size: 10px;
            }}
            .link-text {{
                fill: #ffffff;
                font-size: 8px;
            }}
            #controls {{
                position: absolute;
                top: 10px;
                left: 10px;
                background-color: rgba(0,0,0,0.7);
                padding: 10px;
                border-radius: 5px;
            }}
        </style>
    </head>
    <body>
        <div id="controls">
            <label for="charge">Charge: </label>
            <input type="range" id="charge" min="-1000" max="0" value="-300" step="10">
        </div>
        <svg width="1600" height="900"></svg>
        <script>
            const data = {json.dumps({"nodes": nodes, "links": links})};
            
            const svg = d3.select("svg"),
                width = +svg.attr("width"),
                height = +svg.attr("height");

            const color = d3.scaleOrdinal()
                .domain(["Threat Actor", "Kill Chain Step", "IoC (File Hash)", "IoC (File Name)", "IoC (URL)", "Executable", "VirusTotal"])
                .range(["#ff0000", "#00ff00", "#0000ff", "#ffff00", "#ff00ff", "#00ffff", "#ffa500"]);

            const simulation = d3.forceSimulation()
                .force("link", d3.forceLink().id(d => d.id).distance(150))
                .force("charge", d3.forceManyBody().strength(-300))
                .force("center", d3.forceCenter(width / 2, height / 2))
                .force("collision", d3.forceCollide().radius(30));

            const g = svg.append("g");

            const zoom = d3.zoom()
                .scaleExtent([0.1, 4])
                .on("zoom", zoomed);

            svg.call(zoom);

            function zoomed() {{
                g.attr("transform", d3.event.transform);
            }}

            const link = g.append("g")
                .attr("class", "links")
                .selectAll("line")
                .data(data.links)
                .enter().append("line")
                .attr("stroke-width", 1);

            const node = g.append("g")
                .attr("class", "nodes")
                .selectAll("circle")
                .data(data.nodes)
                .enter().append("circle")
                .attr("r", 10)  // Increased node size
                .attr("fill", d => color(d.group))
                .call(d3.drag()
                    .on("start", dragstarted)
                    .on("drag", dragged)
                    .on("end", dragended));

            const text = g.append("g")
                .attr("class", "text")
                .selectAll("text")
                .data(data.nodes)
                .enter().append("text")
                .text(d => d.name)
                .attr("font-size", 10)
                .attr("dx", 12)
                .attr("dy", 4);

            node.append("title")
                .text(d => {{
                    let title = d.name;
                    if (d.detection_ratio) {{
                        title += `\\nDetection Ratio: ${{d.detection_ratio}}`;
                        title += `\\nFirst Detection: ${{d.first_detection}}`;
                        title += `\\nLast Detection: ${{d.last_detection}}`;
                    }}
                    return title;
                }});

            const linkText = g.append("g")
                .attr("class", "link-text")
                .selectAll("text")
                .data(data.links)
                .enter().append("text")
                .attr("font-size", 8)
                .text(d => d.type);

            simulation
                .nodes(data.nodes)
                .on("tick", ticked);

            simulation.force("link")
                .links(data.links);

            function ticked() {{
                link
                    .attr("x1", d => d.source.x)
                    .attr("y1", d => d.source.y)
                    .attr("x2", d => d.target.x)
                    .attr("y2", d => d.target.y);

                node
                    .attr("cx", d => d.x)
                    .attr("cy", d => d.y);

                text
                    .attr("x", d => d.x)
                    .attr("y", d => d.y);

                linkText
                    .attr("x", d => (d.source.x + d.target.x) / 2)
                    .attr("y", d => (d.source.y + d.target.y) / 2);
            }}

            function dragstarted(d) {{
                if (!d3.event.active) simulation.alphaTarget(0.3).restart();
                d.fx = d.x;
                d.fy = d.y;
            }}

            function dragged(d) {{
                d.fx = d3.event.x;
                d.fy = d3.event.y;
            }}

            function dragended(d) {{
                if (!d3.event.active) simulation.alphaTarget(0);
                d.fx = null;
                d.fy = null;
            }}

            // Add charge slider functionality
            d3.select("#charge").on("input", function() {{
                simulation.force("charge").strength(+this.value);
                simulation.alpha(1).restart();
            }});
        </script>
    </body>
    </html>
    """

    # Write the HTML file
    with open(output_file, 'w') as f:
        f.write(html_content)

    print(f"D3.js visualization has been saved to '{output_file}'")

if __name__ == "__main__":
    input_file = "threat_intel_with_virustotal.json"
    output_file = "security_event_knowledge_graph.html"
    generate_d3_visualization(input_file, output_file)