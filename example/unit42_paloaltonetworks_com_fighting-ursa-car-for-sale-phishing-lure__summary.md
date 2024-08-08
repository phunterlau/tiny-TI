# Threat Intelligence Summary

## Overview
The threat actor identified as **Fighting Ursa** primarily employs **phishing** and **malware distribution** as their methods of attack. The observed attack chain consists of multiple steps, including: 

1. **Delivery**: The initial phase, where malicious files are delivered through URLs tied to specific file hashes.
2. **Exploitation**: The exploitation phase utilizes malicious files to compromise the target system.
3. **Installation**: During this step, the malware installs additional components, executing files that facilitate its operation.
4. **Command and Control (C2)**: The final phase allows the attacker to maintain control over the compromised system.

The attack utilizes various malicious files, including executable files disguised as images and scripts designed to perform unwanted actions on the victim's machine.

## Key Questions for Further Investigation
1. What specific techniques are used in the phishing campaigns to lure victims?
2. Are there any known associations or affiliations of the Fighting Ursa group with other threat actors?
3. What measures can organizations take to mitigate the risks associated with Fighting Ursa's attack methods?
4. Have there been any reported incidents or breaches linked to Fighting Ursa, and what were the impacts?
5. What additional indicators of compromise (IoCs) can be derived from previous attacks attributed to this actor?

## IoCs
- **File Hashes**: 
  - cda936ecae566ab871e5c0303d8ff98796b1e3661885afd9d4690fc1e945640e
  - 7c85ff89b535a39d47756dfce4597c239ee16df88badefe8f76051b836a7cbfb
  - dad1a8869c950c2d1d322c8aed3757d3988ef4f06ba230b329c8d510d8d9a027
  - c6a91cba00bf87cdb064c49adaac82255cbec6fdd48fd21f9b3b96abf019916b
  - 6b96b991e33240e5c2091d092079a440fa1bef9b5aecbf3039bf7c47223bdf96
  - a06d74322a8761ec8e6f28d134f2a89c7ba611d920d080a3ccbfac7c3b61e2e7

- **URLs/IPs**: 
  - https://webhook.site/66d5b9f9-a5eb-48e6-9476-9b6142b0c3ae
  - https://webhook.site/d290377c-82b5-4765-acb8-454edf6425dd
  - https://i.ibb.co/vVSCr2Z/car-for-sale.jpg

- **File Names**: 
  - IMG-387470302099.jpg.exe
  - WindowsCodecs.dll
  - zqtxmo.bat

## VirusTotal Summary
The analysis of the malware samples shows varying degrees of detection across different antivirus engines. For instance, the file hash `cda936ecae566ab871e5c0303d8ff98796b1e3661885afd9d4690fc1e945640e` had a detection ratio of **28/79**, indicating a significant number of engines identified it as malicious. Other samples, such as `dad1a8869c950c2d1d322c8aed3757d3988ef4f06ba230b329c8d510d8d9a027`, had even higher detection rates of **48/79**, suggesting they are well-known threats. Notably, multiple engines flagged these files as Trojans, indicating a malicious intent to compromise systems.