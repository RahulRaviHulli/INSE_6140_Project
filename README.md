# Ghidra Extension for Identification, Analysis, and Mitigation of OS Command Injection Vulnerabilities

### Project Explanation Video Link: https://youtu.be/Bb7l_D6OxlU

## GhidraCommandInjectionChecker

Developed as part of INSE – 6140 – Malware Defenses and Application Security for the Winter 2024 semester under Dr. Makan Pourzandi, the GhidraCommandInjectionChecker is an innovative Ghidra extension. It aims to identify and analyze OS Command Injection vulnerabilities in binary codes, specifically targeting insecure functions that are often exploited in such security breaches.

## Project Description

The GhidraCommandInjectionChecker utilizes Ghidra's static analysis framework to heuristically detect potential command injection vulnerabilities, aiding in the secure assessment of binaries. This project focuses on addressing the significant security challenge posed by command injection, as outlined in CWE-78.

## Team Members and Contributions

- **Rakshith Raj Gurupura Puttaraju** (ID: 40235325): Led the development of the Ghidra extension tailored for command injection analysis, contributing essential functionality for vulnerability detection within the tool.
  
- **Mustafa Talha Ucar** (ID: 40059335): Contributed to identifying insecure functions, played a pivotal role in the extension's design, and participated in various project activities.
  
- **Rahul Ravi Hulli** (ID: 40234542): Focused on a detailed analysis of the MirthConnect application, identifying vulnerable code segments that could lead to remote code execution vulnerabilities, thereby enhancing the tool's detection algorithms.

Each team member equally contributed to various aspects of the project, including the development of the python script to perform ghidra headless anaysis, the in-depth examination of the MirthConnect application, and the overall design and implementation of the GhidraCommandInjectionChecker extension. Their collaborative efforts ensured the successful realization of the project's objectives.

## Project Timeline

- **Feb 6 - Feb 12 (Tool Exploration):** Introduction and setup phase, focusing on understanding Ghidra.
- **Feb 13 - Feb 26 (Extension Development):** Core development phase for the command injection detection extension.
- **Feb 27 - Mar 12 (Binary Creation):** Generation phase for binaries that contain command injection vulnerabilities for testing purposes.
- **Mar 13 - Mar 26 (Validation):** Phase for testing and validating the tool against various scenarios to ensure effectiveness.
- **Apr 3 - Apr 10 (Documentation and Presentation):** Compilation of project documentation and preparation for showcasing the project's findings and capabilities.

## How to Use

Execute the following command from the root directory of the project to run GhidraCommandInjectionChecker:

```bash
python3 analyse.py --ghidra /path/to/ghidra --import /path/to/target/binary
