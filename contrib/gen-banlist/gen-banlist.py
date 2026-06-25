#!/usr/bin/env python3

import os
import tomllib
import argparse

FORMAT_BITCOIN_CORE_CLI = "bitcoin-cli setban {} add {:<8}  # {}"
FORMAT_BITCOIN_CORE_GUI = "setban {} add {:<8}"
FORMAT_PLAIN = "{}"
NEWLINE = "\n"

BAN_TIME_ONE_YEAR = 60 * 60 * 24 * 365

DEFAULT_INPUT_FILE = "entities.toml"

OUTPUT_BITCOIN_CORE_CLI = "banlist_cli.txt"
OUTPUT_BITCOIN_CORE_GUI = "banlist_gui.txt"
OUTPUT_PLAIN = "banlist_plain.txt"

CLI_HEADER = """\
# The banlist starts below.
# This file is not a script! Never use these commands without verifying the file content first!
# An attacker could put a 'bitcoin-cli sendall <ATTACKER ADDRESS>' in here.
# In an attempt to stop you from running this as script I'm adding an 'exit' in here.
echo "You just got your funds stolen."
exit -1
# -----------------------
"""

def main():
    parser = argparse.ArgumentParser(
        prog="gen-banlist",
        description='Generates scripts to ban the IPs listed on the banlist'
    )

    parser.add_argument('input_file', nargs='?', type=argparse.FileType('rb'), default=open(DEFAULT_INPUT_FILE, "rb"), help="the input TOML file to read from")
    parser.add_argument('output_directory', type=str, help='The output path for the generated banlist scripts.')
    parser.add_argument('--bantime', type=int, help="Ban time in seconds (used where supported)", default=BAN_TIME_ONE_YEAR)

    args = parser.parse_args()

    data = tomllib.load(args.input_file)

    # An entity's IPs may be listed inline via "ips" or, for large lists, kept
    # in a separate file referenced by "ips_file". An "ips_file" path is resolved
    # relative to the directory the input TOML file lives in.
    toml_dir = os.path.dirname(os.path.abspath(args.input_file.name))
    for entity in data["entities"]:
        if "ips_file" in entity:
            with open(os.path.join(toml_dir, entity["ips_file"])) as f:
                entity["ips"] = [line.strip() for line in f if line.strip()]

    print("loaded {} entities with {} IP addresses".format(len(data["entities"]), sum(len(e["ips"]) for e in data["entities"])))

    max_ip_length = max(max([len(ip) for ip in e["ips"]]) for e in data["entities"])

    def output_file(name):
        return args.output_directory + "/" + name

    with open(output_file(OUTPUT_BITCOIN_CORE_CLI), 'w') as fcli, open(output_file(OUTPUT_BITCOIN_CORE_GUI), 'w') as fgui, open(output_file(OUTPUT_PLAIN), 'w') as fplain:
        fcli.write(CLI_HEADER + NEWLINE)
        for entity in data["entities"]:
            for ip in entity["ips"]:
                fcli.write(FORMAT_BITCOIN_CORE_CLI.format(ip.ljust(max_ip_length), args.bantime, entity["name"]) + NEWLINE)
                fgui.write(FORMAT_BITCOIN_CORE_GUI.format(ip.ljust(max_ip_length), args.bantime) + NEWLINE)
                fplain.write(FORMAT_PLAIN.format(ip) + NEWLINE)

if __name__ == "__main__":
    main()
