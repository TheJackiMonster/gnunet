#!/usr/bin/env python3

import argparse as ap
import re

filename = r"(/\w+)+\.\w"
main_match = rf"(?P<filename>{filename}):(?P<linenumber>\d+): warning:"
var_def = rf"(?:const)? \w+ \*?\w+"
func_params = rf"\({var_def}(?:, {var_def})*\)"
func_name = r"\w+"

matches = {
    "not an input @file": re.compile(rf"{main_match} the name '{filename}' supplied as the argument in the \file statement is not an input file"),
    "multiple @param docs": re.compile(rf"{main_match} {filename} argument '\w+' from the argument list of \w+ has multiple @param documentation sections"),
    "undocumented param": re.compile(rf"{main_match} {filename} The following parameter of {func_name}{func_params} is not documented:"),
}

parser = ap.ArgumentParser()
parser.add_argument("filename")
args = parser.parse_args()

counts = {k: 0 for k in matches.keys()}

with open(args.filename, "r") as file:
    for line in file.readlines():
        for key, regex in matches.items():
            if regex.match(line):
                counts[key] += 1

print(counts)
