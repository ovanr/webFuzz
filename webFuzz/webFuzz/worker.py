import asyncio
import logging

from aiohttp      import ClientSession,ClientResponse
from bs4          import BeautifulSoup
from typing       import Union, Optional, Dict, Iterator
from itertools    import repeat

# User defined modules
from .environment   import env
from .node          import Node
from .types         import FuzzerLogger, get_logger, HTTPMethod, RequestStatus, Statistics, ExitCode
from .misc          import iter_join
from .mutator       import Mutator
from .node_iterator import NodeIterator
from .crawler       import Crawler
from .parser        import Parser
from .detector      import Detector
from .browser       import Browser

# every how many requests to check if
# we are logged in
LOGGED_IN_CHECK_INTERVAL = 50

class Worker():
    def __init__(self,
                 id_: str, 
                 session: ClientSession, 
                 crawler: Crawler, 
                 mutator: Mutator,
                 parser: Parser,
                 detector: Detector,
                 iterator: NodeIterator,
                 session_node: Node,
                 statistics: Statistics):

        self.id = id_
        self._session = session
        self._crawler = crawler
        self._mutator = mutator
        self._parser = parser
        self._detector = detector
        self._node_iterator = iterator
        self._session_node = session_node
        self._stats = statistics

    @property
    def asyncio_task(self) -> Union[asyncio.Task, None]:
        if hasattr(self, "_task"):
            return self._task
        else:
            return None

    @asyncio_task.setter
    def asyncio_task(self, task: asyncio.Task):
        self._task = task

    def update_stats(self, current_node: Node):
        self._stats.total_cover_score = self._node_iterator.total_cover_score
        self._stats.current_node = current_node
        self._stats.crawler_pending_urls = self._crawler.pending_requests
        self._stats.total_xss = self._detector.xss_count

    @staticmethod
    def has_catchphrase(raw_html: str, catchphrase: str) -> bool:
        if not catchphrase:
            return True

        if catchphrase in raw_html:
            return True

        return False

    async def process_response(self, response: ClientResponse, node: Node) -> RequestStatus:
        logger = get_logger(__name__, self.id)

        try:
            # req.text() can throw UnicodeDecodeError
            # in non utf-8 encoded html documents
            raw_html: str = await response.text()
        except UnicodeDecodeError:
            return RequestStatus.UNSUCCESSFUL_REQUEST
        
        if node.label == 'session_check':
            # special node to check if we are logged in
            if Worker.has_catchphrase(raw_html, env.args.catch_phrase):
                logger.info("Success, we are still logged in")
                return RequestStatus.SUCCESS_FOUND_PHRASE

        soup = None

        if self._detector.xss_precheck(raw_html):
            # html5lib parser is the most identical method to how browsers parse HTMLs
            soup: BeautifulSoup = BeautifulSoup(raw_html, "html5lib")
            self._detector.xss_scanner(node, soup)

        cfg = node.parse_instrumentation(response.headers, self.id)
            
        if not self._node_iterator.add(node, cfg):
            logger.info("Not interesting")
            return RequestStatus.SUCCESS_NOT_INTERESTING

        if soup is None:
            soup: BeautifulSoup = BeautifulSoup(raw_html, "html5lib")

        links = self._parser.parse(node, soup)
        self._crawler += links

        return RequestStatus.SUCCESS_INTERESTING


    async def handle_request(self, new_request: Node) -> RequestStatus:
        logger = get_logger(__name__, self.id)

        if new_request.method == HTTPMethod.GET:
            send_request = self._session.get
        elif new_request.method == HTTPMethod.POST:
            send_request = self._session.post
        else:
            logger.error("Unimplemented HTTP method")
            return RequestStatus.UNIMPLEMENTED_METHOD

        logger.info("sending request: %s", new_request.url)

        async with send_request(new_request.url,
                                headers={ 'REQ-ID' : self.id},
                                params=new_request.params[HTTPMethod.GET],
                                data=new_request.params[HTTPMethod.POST],
                                trace_request_ctx=new_request) as r:

            self._stats.total_requests += 1
            exit_early = False

            if logger.getEffectiveLevel() == logging.DEBUG:
                # needed since response body is loaded strictly
                logger.debug("Dumping html %s: ", await r.text())

            if r.status >= 400:
                logger.warning('Got code %d from %s', r.status, r.url)

                if env.args.ignore_404 and r.status == 404: exit_early = True
                if env.args.ignore_4xx: exit_early = True

            if r.content_type and r.content_type != 'text/html':
                logger.info('Got non html payload: %s', r.content_type)
                exit_early = True

            if exit_early:
                logger.info('destroying request..')
                return RequestStatus.INVALID_RESPONSE

            status = await self.process_response(r, new_request)
            logger.info("Request Completed: %s", new_request)

            self.update_stats(new_request)
            
            return status

    async def run_worker(self) -> ExitCode:
        logger = get_logger(__name__, self.id)
        logger.info("Worker reporting Active")

        if env.args.catch_phrase:
            periodic = repeat(self._session_node)
        else:
            # create an empty iterator
            periodic = repeat(None, 0)

        for (src, new_request) in iter_join(primary=self._crawler,
                                            secondary=self._node_iterator, 
                                            periodic=periodic,
                                            interval=LOGGED_IN_CHECK_INTERVAL):
            if src == self._crawler:
                logger.info("Chosen an unvisited node")

            elif src == self._node_iterator:
                # this request isn't new i.e. it came from NodeIterator
                # thus needs to be mutated first
                new_request = self._mutator.mutate(new_request, 
                                                   self._node_iterator.node_list)
                logger.info("Chosen a mutated node")

            try:
                return_code = await self.handle_request(new_request)
            except Exception as e:
                logger.error(e, exc_info=True)
                return_code = RequestStatus.UNSUCCESSFUL_REQUEST

            if src == periodic and \
                return_code != RequestStatus.SUCCESS_FOUND_PHRASE:
                logger.warning("Fuzzer has been logged out...")

                return ExitCode.LOGGED_OUT

            if env.shutdown_signal != ExitCode.NONE:
                return env.shutdown_signal

        logger.error("Aborting due to lack of paths")
        return ExitCode.EMPTY_QUEUE
