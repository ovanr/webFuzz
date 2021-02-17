#!/usr/bin/env python3.9
"""
The entry point to the webFuzz fuzzing tool. In this module, arguments
given by the user are parsed and the fuzzing mode in which the user desires
webFuzz to run, is initialised.
"""
import asyncio
import os

from webFuzz.fuzzer import Fuzzer
from webFuzz.types import Arguments, RunMode

def main():
    description = 'webFuzz is a grey-box fuzzer for web applications.'
    version = 1.1
    args = Arguments(version=version, description=description, 
                     usage='%(prog)s [options] -r/--run <mode> <URL>',
                     add_help=True).parse_args()
    
    fuzzer = Fuzzer(args)

    if args.run_mode == RunMode.AUTO:
       # asyncio.run(f.run_curses())
       pass
    elif args.run_mode == RunMode.SIMPLE:
        asyncio.run(fuzzer.run_simple(printToFile=False))
    elif args.run_mode == RunMode.FILE:
        asyncio.run(fuzzer.run_simple(printToFile=True))
    elif args.run_mode ==  RunMode.MANUAL: 
        # NOT COMPLETED YET
        pass

main()
