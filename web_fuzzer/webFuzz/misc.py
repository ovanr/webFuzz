import logging
import os

from typing       import Callable, Iterator, Any, Dict, Tuple
from difflib      import SequenceMatcher

from .types       import Arguments, get_logger, ExitCode
from .environment import env

def object_to_tuple(d: object) -> tuple:
    if isinstance(d, str) or isinstance(d, int) or isinstance(d, float):
        return tuple(str(d))

    if isinstance(d, list):
        d.sort()
        return tuple([object_to_tuple(x) for x in d])
    
    if isinstance(d, dict):
        keys = list(d.keys())

        keys.sort()
        return tuple([(k, object_to_tuple(d[k])) for k in keys])
    
    return tuple('')

def retrieve_cookies(args: Arguments) -> Dict[str,str]:
    logger = get_logger(__name__)
            
    # since the chromedriver is version dependant
    # we defer loading .browser module unless the flag is passed
    from .browser import get_cookies

    if not os.path.isabs(args.driverFile):
        args.driverFile = os.path.dirname(__file__) + '/../' + args.driverFile

        cookies = {c['name']: c['value'] for c in get_cookies(args.driverFile, args.URL)}

        logger.info("got cookies: %s", cookies)

        return cookies

    return {}

def retrieve_headers() -> Dict[str,str]:
    return {
        'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
        'accept-language': 'en-GB,en;q=0.9,en-US;q=0.8,el;q=0.7',
        'accept': 'text/html,application/xhtml+xml'
    }

def chainIter(iter1: Iterator, iter2: Iterator) -> Iterator:
    while True:
        for elem in iter1:
            yield (iter1, elem)

        try:
            yield (iter2, next(iter2))
        except StopIteration:
            return

def sigint_handler(*args: Any, **kwargs: Any) -> None:
    logger = get_logger(__name__)
    logger.info('SIGINT received')
    print("\nFuzzer PAUSED")
    while True:
        try:
            response = input('\nAre you sure you want to exit? Type (yes/no):\n')
            if response == "yes":
                env.shutdown_signal = ExitCode.USER
                return
            if response == "debug":
                root = get_logger()
                root.setLevel(logging.DEBUG)
                return
            if response == "info":
                root = get_logger()
                root.setLevel(logging.INFO)
                return
            else:
                return
        except KeyboardInterrupt:
            pass

def sigalarm_handler(*args: Any, **kwargs: Any) -> None:
    logger = get_logger(__name__)
    logger.warning('Reached timeout, stopping fuzzing process')
    env.shutdown_signal = ExitCode.TIMEOUT

def longest_str_match(str1: str, str2: str) -> int:
    (_,__,size) = SequenceMatcher(None, str1, str2).find_longest_match(0, len(str1), 0, len(str2))
    return size
