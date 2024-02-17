import sys
import json
import textwrap

def wrap_line(value):
    return textwrap.fill(value, width=65)

def format_vector(vector_keys, vector_fname):
    with open(vector_fname, "r") as fh:
        data = json.load(fh)
        formatted = "~~~\n"
        for i, entry in enumerate(data):
            formatted = formatted + ("// Test vector %d" % (i+1)) + "\n"
            for key in vector_keys:
                if key in entry:
                    formatted = formatted + wrap_line(key + ": " + str(entry[key])) + "\n"
            formatted = formatted + "\n"
        print(formatted + "~~~\n")

ordered_keys = [
    "p", 
    "q", 
    "d", 
    "e",
    "n",
    "msg", 
    "info", 
    "eprime", 
    "r",
    "salt", 
    "blind_msg", 
    "blind_sig", 
    "sig",
]
format_vector(ordered_keys, sys.argv[1])
