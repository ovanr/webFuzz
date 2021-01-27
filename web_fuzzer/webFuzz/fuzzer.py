"""
    Implementation of a fuzzing tool that will provide invalid, unexpected, malicious
    or random data as inputs to a computer program. The program is then
    monitored for exceptions such as rxss, sqli injections, crashes, 
    failing built-in code assertions, long execution times and potential memory leaks.
"""

import aiohttp
import asyncio
import curses
import http.client
import json
import logging
import random
import signal

from typing         import List
from aiohttp.client import ClientSession, TraceConfig

# User defined modules
from .worker        import Worker
from .curses_menu   import Curses_menu
from .environment   import env
from .node          import Node
from .types         import Arguments, FuzzerLogger, InstrumentArgs, OutputMethod, get_logger, HTTPMethod, Statistics, ExitCode
from .misc          import retrieve_cookies, retrieve_headers, sigalarm_handler, sigint_handler
from .mutator       import Mutator
from .node_iterator import NodeIterator
from .crawler       import Crawler
from .parser        import Parser
from .detector      import Detector
from .simple_menu   import Simple_menu

class Fuzzer:
    def __init__(self, args: Arguments) -> None:
        """
            Initialisation of a webFuzz instance
        """
        env.args = args

        FuzzerLogger.init_logging(args)

        logger = get_logger(__name__)
        logger.debug(args)

        self.timeout = args.timeout

        self.worker_count = args.worker

        meta = json.loads(open(args.metaFile).read())
        # throws exception on invalid format
        env.instrument_args = InstrumentArgs(meta)

        if env.instrument_args.output_method == OutputMethod.HTTP:
            # expect instr. feedback in http-header form so adjust this
            http.client._MAXHEADERS = max(10000, env.instrument_args.basic_blocks) # type:ignore

        cookies = {}
        if args.session:
            cookies = retrieve_cookies(args)

        headers = retrieve_headers()

        self._session_data = {"cookies": cookies, "headers": headers}

        self._node_iterator = NodeIterator()
        
        self._mutator = Mutator()

        self._parser = Parser()

        self._detector = Detector()

        # TODO: parse the url first, it may contain query parameters
        # TODO: option to specify multiple starting points
        init_node = Node(url=args.URL, method=HTTPMethod.GET)
        self._crawler = Crawler(blocklist=args.block,
                                crawler_unseen=set([init_node]))

        self.stats = Statistics(init_node)


    @staticmethod
    def create_trace_configs() -> List[TraceConfig]:

        async def on_request_start(session: ClientSession, 
                                   trace_config_ctx, 
                                   params: aiohttp.TraceRequestStartParams) -> None:
                            
            trace_config_ctx.start = asyncio.get_event_loop().time()

        async def on_request_end(session: ClientSession, 
                                 trace_config_ctx, 
                                 params: aiohttp.TraceRequestEndParams) -> None:
                                 
            elapsed_time = asyncio.get_event_loop().time() - trace_config_ctx.start
            trace_config_ctx.trace_request_ctx.exec_time = elapsed_time

        exec_time_config = TraceConfig()
        exec_time_config.on_request_start.append(on_request_start)
        exec_time_config.on_request_end.append(on_request_end)

        return [exec_time_config]

    async def create_workers(self):
        for count in range(self.worker_count):
            worker_id = str(random.randrange(10000, 1000000))
            worker = Worker(worker_id,
                            self._session,
                            self._crawler,
                            self._mutator,
                            self._parser,
                            self._detector,
                            self._node_iterator,
                            self.stats)

            self.workers.append(worker)
            worker.asyncio_task = asyncio.create_task(worker.run_worker())

            if count == 0:
                # if it is the first worker spawned
                # wait until at least one request/response cycle is done
                # this is needed because workers that find an empty queue exit
                await asyncio.sleep(8)

            if env.shutdown_signal != ExitCode.NONE:
                break
    
    async def exit_session(self):
        logger = get_logger(__name__)

        await self._session.close()

        logger.warning('Shutting Down Initiated.')

        logging.shutdown()

    async def fuzzer_loop(self) -> ExitCode:
        logger = get_logger(__name__)

        # timeout per link in seconds
        timeout = aiohttp.ClientTimeout(total=env.args.request_timeout) # type: ignore
        trace_configs = Fuzzer.create_trace_configs()

        conn = aiohttp.TCPConnector(limit=self.worker_count, limit_per_host=self.worker_count)

        self._session = aiohttp.ClientSession(cookies=self._session_data["cookies"],
                                              headers=self._session_data["headers"],
                                              connector=conn,
                                              timeout=timeout,
                                              trace_configs=trace_configs)

        signal.alarm(self.timeout)

        logger.info("Spawning %d workers", self.worker_count)

        self.workers = []

        await self.create_workers()

        exit_code = ExitCode.NONE
        
        # wait for them to finish
        for worker in self.workers:
            exit_code: ExitCode = await worker.asyncio_task

        env.shutdown_signal = exit_code

        await self.exit_session()

        return env.shutdown_signal

    @staticmethod
    def register_signal_handlers() -> None:        
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGINT, sigint_handler)
        loop.add_signal_handler(signal.SIGALRM, sigalarm_handler)

    """
        Starting point for the Fuzzer execution with simple print interface. Here you can specify
        async tasks to run *concurrently* and register async safe Signal Handlers
    """
    async def run_simple(self, printToFile: bool) -> ExitCode:
        self.register_signal_handlers()
        fuzzer = self

        if printToFile:
            f = open("/tmp/fuzzer_stats", "w+")
        
            def printer(line):
                f.write(line + "\n")
            def refresh():
                f.truncate(0)
                f.seek(0)

            sm = Simple_menu(fuzzer, printer, refresh, f.flush)
        else:   
            sm = Simple_menu(fuzzer)

        print_stats_task = asyncio.create_task(sm.print_stats())
        fuzzer_loop_task = asyncio.create_task(self.fuzzer_loop())

        await print_stats_task
        exit_code = await fuzzer_loop_task

        return exit_code

    """
        Starting point for the Fuzzer execution with curses interface. Here you can specify
        async tasks to run *concurrently* and register async safe Signal Handlers
    """
    async def run_curses(self) -> None:
        self.register_signal_handlers()
        fuzzer = self

        # TODO: UPDATE ME

        cm = Curses_menu(fuzzer)
        interface = asyncio.create_task(curses.wrapper(cm.draw_menu))
        await interface