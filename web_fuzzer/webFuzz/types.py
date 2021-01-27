
from __future__ import annotations

import logging

from tap        import Tap
from typing     import Any, List, Dict, Set, Union, NamedTuple
from enum       import Enum
from os         import mkdir, unlink, symlink
from datetime   import datetime
from jsonschema import validate

Numeric = Union[int, float]

Label = int
Bucket = int

CFG = Dict[Label, Bucket]
CFGTuple = NamedTuple("CFGTuple", [("xor_cfg", CFG), ("single_cfg", CFG)])

BlockedLink = NamedTuple("BlockedLink", [("url",str), ("key",str), ("val", str)])

class FuzzerException(Exception):
   pass

class ExtendedEnum(Enum):
    def __str__(self):
        return str(self.name)
    def __repr__(self):
        return self.__str__()
    def __lt__(self, obj):
        return self.value < obj.value
    
class RequestStatus(ExtendedEnum):
    SUCCESS_INTERESTING = 0
    SUCCESS_NOT_INTERESTING = 1
    UNSUCCESSFUL_REQUEST = 2
    INVALID_RESPONSE = 3
    UNIMPLEMENTED_METHOD = 4

class ExitCode(ExtendedEnum):
    NONE = 0
    USER = 1
    EMPTY_QUEUE = 2
    TIMEOUT = 3

class HTTPMethod(ExtendedEnum):
    GET = 0
    POST = 1

class XSSConfidence(ExtendedEnum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

Params = Dict[HTTPMethod, Dict[str, List[str]]]
XssEntry = NamedTuple("XssEntry", [("param",str), ("xss_code",int)])
XssParams = Dict[HTTPMethod, Set[XssEntry]]

class Statistics():
    current_cover_score: float = 0.0
    total_cover_score: float = 0.0
    crawler_pending_urls: int = 0
    total_requests: int = 0
    total_xss: int = 0
    current_node: Any # actual type: Node (error due to cyclic import)
    
    def __init__(self, initial_node):
        self.current_node = initial_node

# CLI Arguments

class RunMode(ExtendedEnum):
    SIMPLE = "simple"
    FILE = "file"
    AUTO = "auto"
    MANUAL = "manual"

class Arguments(Tap):
    verbose: int = 0
    """Increase verbosity"""

    session: bool = False
    """Login through the browser and get cookies"""

    ignore_404: bool = False
    """Do not fuzz links that return 404 code"""

    ignore_4xx: bool = False
    """Do not fuzz links that return 4xx code"""

    metaFile: str = "./instr.meta"
    "Specify the location of instrumentation meta file (instr.meta)"

    block: List[BlockedLink] = []
    """Specify a link to block the fuzzer from using, Form = 'url|parameter|value'"""

    worker: int = 1
    """Specify the number of workers to spawn that will concurrently send requests"""

    unique_anchors: bool = False
    """Treat urls with different anchors as different urls"""

    driverFile: str = "./drivers/chromedriver"
    """Specify the location of the web driver (used in -s flag)"""

    timeout: int = 0
    """Set fuzzing session timeout value in seconds (0 indicates no timeout)"""

    request_timeout: int = 35
    """Set the per request timeout in seconds"""

    maxXss: int = 3
    """Set the maximum XSS payloads to inject in a single parameter"""

    runMode: RunMode = RunMode.SIMPLE
    """Select the run mode. Modes: auto, manual, simple, file"""

    URL: str
    'Specify the inital URL to start fuzzing from'


    def __init__(self, version, *args, **kwargs):
        self.version = version
        super().__init__()

    def configure(self) -> None:
        def parse_single_block_opt(value: str) -> BlockedLink:
            (url, key, val) = value.split("|")
            return BlockedLink(url=url, key=key, val=val)

        self.add_argument('-v', '--verbose', action='count')
        self.add_argument('-s', '--session')
        self.add_argument('-m', '--metaFile')
        self.add_argument('-b', '--block', type=parse_single_block_opt, nargs="*")
        self.add_argument('-w', '--worker')
        self.add_argument('-t', '--timeout')
        
        self.add_argument('-r', "--runMode")
        self.add_argument('URL')

        self.add_argument('--version', help="Prints webFuzz latest version", action='version',
                          version='webFuzz v{VERSION}'.format(VERSION=self.version))

        self.add_argument('-r', '--runMode', type=RunMode)


# Instrumentation Arguments

# Instrumentation should output a instr.meta file with this format.
# This is needed to calculate the coverage stats.
INSTR_META_SCHEMA = {
    "title": "instrument-meta",
    "type": "object",
    "properties": {
        "basic-block-count": { "type": "integer"},
        "output-method": {
            "type": "string",
            "pattern": "^(file|http)$"
        },
        "instrument-policy": {
            "type": "string",
            "pattern": "^(edge|node-edge|node)$"
        },
        "edge-count": { "type": "integer"}
    },
    "required": ["basic-block-count", "output-method", "instrument-policy"]
}

class OutputMethod(ExtendedEnum):
    FILE = 0
    HTTP = 1

class Policy(ExtendedEnum):
    NODE = 0
    EDGE = 1
    NODE_EDGE = 2

class InstrumentArgs():
    basic_blocks: int
    edges: int
    output_method: OutputMethod
    policy: Policy

    def __init__(self, meta_json):
        validate(instance=meta_json, schema=INSTR_META_SCHEMA)

        self.basic_blocks = int(meta_json['basic-block-count'])
        self.output_method = OutputMethod[meta_json['output-method'].upper()]
        self.policy = Policy[meta_json['instrument-policy'].upper().replace('-', '_')]

        if self.policy != Policy.NODE:
            self.edges = int(meta_json['edge-count'])

# Logging

class FuzzerLogger(logging.Logger):
    TRACE = logging.DEBUG - 5

    @staticmethod
    def init_logging(args: Arguments):
    
        logging.addLevelName(FuzzerLogger.TRACE, 'TRACE')
        logging.setLoggerClass(FuzzerLogger)
        
        file_handler = FuzzerLogger.init_file_handler()

        # initialize root logger and let descendant module loggers
        # propagate their logs to root module handlers
        # note: descendant loggers will inherit root's log level
        # see: https://docs.python.org/3/_images/logging_flow.png

        rootLogger = get_logger()
        rootLogger.addHandler(file_handler)

        levels = [logging.ERROR,
                  logging.WARNING,
                  logging.INFO,
                  logging.DEBUG,
                  FuzzerLogger.TRACE]

        rootLogger.setLevel(levels[ min(args.verbose, len(levels)-1) ])

    @staticmethod
    def init_file_handler():
        try:
            mkdir("./log")
            unlink("fuzzer.log")
        except FileExistsError:
            unlink("fuzzer.log")
            pass
        except FileNotFoundError:
            pass

        # Creation of the current run's log file name
        dt = datetime.now()
        filename = f"./log/webFuzz_{dt.day}-{dt.month}_{dt.hour}:{dt.minute}.log"

        # Creation of a symlink to the latest fuzzer log for ease of access
        symlink(filename, "./fuzzer.log")

        # Format of each line in the log file using custom formatter
        # defined in CustomFormat() class
        file_handler = logging.FileHandler(filename)
        file_handler.setFormatter(CustomFormatter())
        file_handler.setLevel(FuzzerLogger.TRACE)

        return file_handler

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def trace(self, *args, **kwargs):
        self.log(FuzzerLogger.TRACE, *args, **kwargs)
    

def get_logger(name: str = "", worker_id: str = "") -> FuzzerLogger:
    name += "/" + worker_id if worker_id else ""

    return logging.getLogger(name) # type: ignore


class CustomFormatter(logging.Formatter):
    """
        Logging Formatter to add colors and add worker id to log entry
    """
    green = "\x1b[32;11m"
    grey = "\x1b[37;11m"
    cyan = "\x1b[96;11m"
    yellow = "\x1b[33;11m"
    red = "\x1b[31;21m"
    bold_red = "\x1b[31;21m"
    reset = "\x1b[0m"

    level_color = {
        FuzzerLogger.TRACE: green,
        logging.DEBUG: grey,
        logging.INFO: cyan,
        logging.WARNING: yellow,
        logging.ERROR: red,
        logging.CRITICAL: bold_red
    }
    
    default_fmt = "[%(asctime)s] %(name)s %(levelname)s %(funcName)s(%(lineno)d) %(message)s"

    def format(self, record):
        # workers use a different logger name format
        # format: {actual logger name}/id
        if '/' in record.name:
            (logname, work_id) = record.name.split('/')
            record.name = logname
            worker_fmt = f"[%(asctime)s] %(name)s %(levelname)s [Worker {work_id}] %(funcName)s(%(lineno)d) %(message)s"
            format_str = worker_fmt
        else:
            format_str = self.default_fmt

        fmt = self.level_color[record.levelno] + format_str + self.reset

        formatter = logging.Formatter(fmt)
        return formatter.format(record)