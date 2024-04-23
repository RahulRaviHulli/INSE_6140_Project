#!/usr/bin/env python3
"""
A script to automate binary analysis with Ghidra in headless mode.
It takes in the path to the Ghidra installation and the binary file to be analyzed,
constructs the necessary command, and executes the analysis.
"""

import argparse
from pathlib import Path
import subprocess

# Default directory name for plugins
DEFAULT_PLUGIN_DIR = 'plugins'

def execute_ghidra_analysis(command: list):
    """Executes Ghidra analysis command and handles exceptions."""
    try:
        subprocess.run(command, stderr=subprocess.STDOUT, check=True, cwd=Path.cwd())
    except subprocess.CalledProcessError as error:
        print(f'Execution failed with status: {error.returncode}')

def build_analysis_command(ghidra_path: Path, binary_path: Path) -> list:
    """Builds the command for running Ghidra in headless mode."""
    ghidra_headless_script = ghidra_path / 'support' / 'analyzeHeadless'
    project_dir = Path.cwd()
    temp_dir = project_dir / 'tmp'
    temp_dir.mkdir(exist_ok=True)  # Ensures temp directory exists

    # Constructing the command
    analysis_command = [
        str(ghidra_headless_script), str(temp_dir), 'PcodeExtractor',
        '-import', str(binary_path),
        '-postScript', 'CommandInjectionAnalyzer.java', str(temp_dir / (binary_path.name + '.json')),
        '-scriptPath', str(project_dir), '-deleteProject'
    ]

    return analysis_command

def ensure_plugin_directory(path: Path):
    """Ensures that a plugin directory exists at the dgiven path."""
    (path / DEFAULT_PLUGIN_DIR).mkdir(exist_ok=True)

def is_plugin_in_classpath(plugin_location: Path) -> bool:
    """Checks if a Gson JAR plugin is present in the classpath."""
    return any(plugin_location.glob('gson*.jar'))

def validate_ghidra_directory(arg_parser, dir_path: str) -> Path:
    """Validates the provided path as a directory containing 'ghidra'."""
    path = Path(dir_path)
    if path.is_dir() and 'ghidra' in dir_path:
        return path
    arg_parser.error(f'The path {dir_path} is not a valid Ghidra directory.')

def validate_binary_file(arg_parser, file_path: str) -> Path:
    """Validates the provided path as a file."""
    path = Path(file_path)
    if path.is_file():
        return path
    arg_parser.error(f'The file {file_path} could not be found.')

def parse_arguments():
    """Parses command line arguments for Ghidra path and binary path."""
    parser = argparse.ArgumentParser(description='Automate binary analysis with Ghidra.')
    parser.add_argument('-g', '--ghidra', required=True, help='Path to Ghidra installation.', type=lambda p: validate_ghidra_directory(parser, p))
    parser.add_argument('-i', '--import', dest='binary', required=True, help='Binary file to analyze.', type=lambda f: validate_binary_file(parser, f))

    return parser.parse_args()

def main():
    """Main function to parse arguments and run the Ghidra analysis."""
    args = parse_arguments()

    # Construct and run the Ghidra analysis command
    command = build_analysis_command(args.ghidra, args.binary)
    execute_ghidra_analysis(command)

if __name__ == '__main__':
    main()
