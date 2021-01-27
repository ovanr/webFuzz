"""
   This module stores an environment 'env' (cli-arguments, etc.)
   variable which will be initialised once, upon module import
   and only that should be imported by other modules. The Fuzzer class
   will set env.args to a local variable at the initialisation phase.
"""


from .types import Arguments, ExitCode, InstrumentArgs
from typing import Optional


class Environment:
    args: Optional[Arguments] = None
    instrument_args: Optional[InstrumentArgs] = None
    shutdown_signal: ExitCode = ExitCode.NONE

    def __init__(self):
        """ Initialisation of Fuzzer environment. Currently it consists
            of the cli-arguments (self.args) and instrumentation_args that
            are read from instr.meta file.
        """
        pass

env = Environment()
