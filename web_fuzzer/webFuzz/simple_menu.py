import asyncio
import time
import sys

from os             import system
from typing         import Callable

from .types         import ExitCode, get_logger
from .environment   import env

def clear(): 
    return system('clear')

"""
    A simple front-end interface for displaying fuzzer statistics
"""
class Simple_menu:

    """
        Initialization point

        :param fuzzer_object: the actual instance of Fuzzer Class
        :type Fuzzer: Fuzzer Object
    """
    def __init__(self, 
                 fuzzer_object, # actual type: Fuzzer (error due to cyclic import)
                 output_func: Callable = print, 
                 refresh_func: Callable = clear, 
                 flush_func: Callable = sys.stdout.flush):

        self.fuzzer = fuzzer_object
        self.printer = output_func
        self.printer_refresh = refresh_func
        self.printer_flush = flush_func

    """
        Run interface. Function doesn't return
    """
    async def print_stats(self) -> None:
        logger = get_logger(__name__)

        past_count = 0
        throughput = 0
        past_time = time.clock_gettime(time.CLOCK_MONOTONIC)
        start_time = past_time

        while True:
            await asyncio.sleep(0.2)

            self.printer_refresh()
            
            current_time = time.clock_gettime(time.CLOCK_MONOTONIC)

            if (current_time - past_time > 2):
                throughput = (self.fuzzer.stats.total_requests - past_count) / \
                             (current_time - past_time)

                past_count = self.fuzzer.stats.total_requests
                past_time = current_time


            self.printer("webFuzz\n-----\n")
            self.printer("Stats\n")

            self.printer('Runtime: {:0.2f} min'.format((current_time - start_time) / 60))
            self.printer('Total Requests: {:d}'.format(self.fuzzer.stats.total_requests))
            self.printer('Throughput: {:0.2f} requests/s'.format(throughput))
            self.printer('Crawler Pending URLs: {:d}'.format(self.fuzzer.stats.crawler_pending_urls))
            self.printer('Current Coverage Score: {:0.4f}%'.format(self.fuzzer.stats.current_node.cover_score))
            self.printer('Total Coverage Score: {:0.4f}%'.format(self.fuzzer.stats.total_cover_score))
            self.printer('Possible XSS: {:d}'.format(self.fuzzer.stats.total_xss))


            self.printer('Executing link: {:s}'.format(self.fuzzer.stats.current_node.url[:105]))
            self.printer('Response time: {:0.2f} sec'.format(self.fuzzer.stats.current_node.exec_time))

            if self.fuzzer.stats.current_node.is_mutated:
                self.printer('State: Fuzzing')
            else:
                self.printer('State: Crawling')

            if current_time - past_time > 1:
                logger.info("Total Cov: %0.4f, Throughput: %0.2f", \
                            self.fuzzer.stats.total_cover_score, throughput)

            self.printer_flush()

            if env.shutdown_signal != ExitCode.NONE:
                print("Exit Initiated. Please wait, this may take a few seconds...")
                return