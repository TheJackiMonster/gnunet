#!/usr/bin/env python3

import argparse as ap
import re
import sys

def sep_re(field, separator):
    return rf"{field}(?:{separator}{field})*"

fileclass = r"[\w-]"
filename = rf"{fileclass}+"
# filename = rf"(/{fileclass}+)+\.\w"
filepath = rf"{sep_re(filename, '/')}\.(?:\w+)"
main_match = rf"(?P<path>/{filepath}|\[generated\]):(?P<linenumber>\d+): warning:"
type_name = rf"(?:const )?(?:unsigned (?:long )?|struct |enum )?(?:\w+)(?: \*?const)? \*{{0,3}}"
var_def = rf"{type_name}\w+(?:\[(?:\(\d+/\d+\))?\])?"
func_params = rf"\({sep_re(var_def, ', ')}(?:,\.\.\.)?\)"
simple_name = r"\w+"
func_name = simple_name
verbose_name = rf"{sep_re(simple_name, ' ')}"
command_re = "(?:</[^>]+>|\\\w+)"
macro_params = rf"\({sep_re(simple_name, ', ')}(?:,\.\.\.)?\)"

matches = {
    "not an input @file": re.compile(rf"{main_match} the name '(?P<name>{filepath}|{simple_name})' supplied as the argument in the \\file statement is not an input file"),
    "multiple @param docs": re.compile(rf"{main_match} argument '\w+' from the argument list of \w+ has multiple @param documentation sections"),
    "undocumented param (message)": re.compile(rf"{main_match} The following parameters? of {func_name}(?:{func_params}|{macro_params}) (?:is|are) not documented:"),
    "undocumented param (name)": re.compile(r"  parameter '[\w.]+'"),
    "explicit link not resolved": re.compile(rf"{main_match} explicit link request to '\w+(?:\(\))?' could not be resolved"),
    "unknown command": re.compile(rf"{main_match} Found unknown command '\\\w+'"),
    "missing argument": re.compile(rf"{main_match} argument '\w+' of command @param is not found in the argument list of {func_name}(?:{func_params}|{macro_params})"),
    "eof inside group": re.compile(rf"{main_match} end of file while inside a group"),
    "eof inside comment": re.compile(rf"{main_match} Reached end of file while still inside a \(nested\) comment. Nesting level \d+ \(probable line reference: \d+\)"),
    "blank": re.compile(rf"^\s*$"),
    "eof inside code block (line 1)": re.compile(rf"{main_match} reached end of file while inside a 'code' block!"),
    "eof inside code block (line 2)": re.compile(rf"The command that should end the block seems to be missing!"),
    "title mismatch": re.compile(rf"{main_match} group (?P<group_id>\w+): ignoring title \"(?P<new_title>{verbose_name})\" that does not match old title \"(?P<old_title>{verbose_name})\""),
    "end of comment expecting command": re.compile(rf"{main_match} end of comment block while expecting command {command_re}"),
    "no matching tag": re.compile(rf"{main_match} found </(?P<tag>[^>]+)> tag without matching <(?P=tag)>"),
    "documented empty return type": re.compile(rf"{main_match} documented empty return type of {func_name}"),
    "unsupported tag": re.compile(rf"{main_match} Unsupported xml/html tag <(?P<tag>[^>]+)> found"),
    "expected whitespace after command": re.compile(rf"{main_match} expected whitespace after \\(?P<command>\w+) command"),
    "illegal command": re.compile(rf"{main_match} Illegal command (?P<illegal_cmd>(?:@|\\)\w+) as part of a (?P<command>\\\w+) command"),
    "undeclared symbol": re.compile(rf"{main_match} documented symbol '\w+' was not declared or defined\."),
    "nameless member": re.compile(rf"{main_match} member with no name found."),
    "end of empty list": re.compile(rf"{main_match} End of list marker found without any preceding list items"),
#    "": re.compile(rf"{main_match} "),
}

parser = ap.ArgumentParser()
parser.add_argument("filename")
args = parser.parse_args()

counts = {**{k: 0 for k in matches.keys()},
          **{"unsorted":0}}

with open(args.filename, "r") as file:
    for line in file.readlines():
        for key, regex in matches.items():
            if regex.match(line):
                counts[key] += 1
                break
        else:
            print(line.strip("\n"), file=sys.stderr)
            counts["unsorted"] += 1

print(counts)
