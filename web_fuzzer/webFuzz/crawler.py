import re
from typing     import Dict, List, Set

from .types     import HTTPMethod, BlockedLink, List
from .misc      import get_logger
from .node      import Node

CRAWLER_PER_BASE_LIMIT = 200

Hash = int
Url = str
BaseURLCounter = Dict[HTTPMethod, Dict[Url, int]]

class Crawler:
    def __init__(self, crawler_unseen: Set[Node] = None, blocklist: List[BlockedLink] = []):
        if not crawler_unseen:
            self._crawler_unseen: Set[Node] = set()
        else:
            self._crawler_unseen: Set[Node] = crawler_unseen
      
        self._blocklist = blocklist
        self._crawler_seen_full: Set[Hash] = set()
        self._crawler_seen_base: BaseURLCounter  = { HTTPMethod.GET: {}, HTTPMethod.POST: {} }

    @property
    def pending_requests(self) -> int:
        return len(self._crawler_unseen)

    """
        Check if the request to be sent matches the criteria of a blocked link

        :param new_request: the request that we want to check
        :type links: Node
        :return: if the request is allowed to be sent
        :rtype: bool
    """
    def _blocklist_allows(self, new_request: Node):
        logger = get_logger(__name__)

        def check_in_params(link: BlockedLink, params: Dict[str, List[str]]):
            for key in params.keys():
                if not re.search(link.key, key, re.IGNORECASE):
                    continue
                if not link.val:
                    return False
                    
                for value in params[key]:
                    if re.search(link.val, value, re.IGNORECASE):
                        logger.info("Blocked %s", new_request)
                        return False

        for link in self._blocklist:
            if not re.search(link.url, new_request.url, re.IGNORECASE):
                continue

            if not link.key or \
               not check_in_params(link, new_request.params[HTTPMethod.GET]) or \
               not check_in_params(link, new_request.params[HTTPMethod.POST]):
                return False
               
        return True
    
    """
        Add to crawler the new links that
        have been found but check that we
        haven't already visited any one of them first

        :param links: the new links to add
        :type links: Set[Node]
        :return: the updated crawler object
        :rtype: Crawler
    """
    def __add__(self, links: Set[Node]):
        if not isinstance(links, set):
            raise NotImplementedError()

        logger = get_logger(__name__)

        if not links:
            return self

        # since we do not need to store the whole Node object
        # for keeping track which requests have been sent in the
        # past, but only their hash, we compare hashes
        # instead of nodes, and filter out already seen links
        # TODO: there must be a cleaner way to do this
        hash_of_links = set(map(lambda link: link.__hash__(), links))
        uniq_hashes = hash_of_links - self._crawler_seen_full
        uniq_links:Set[Node] = set(filter(lambda link: link.__hash__() in uniq_hashes, links))

        self._crawler_unseen = self._crawler_unseen | uniq_links

        logger.trace("New links found: %s", uniq_links)

        return self

    """
        Check if the base url of the new request did not surpass the limit.
        Each base url (without the query,fragment string) is only allowed to be sent
        in total CRAWLER_PER_BASE_LIMIT number of times. This is a simple
        way to stop urls with nonce parameter to be constantly sent

        :param new_request: the request that we want to check
        :type links: Node
        :return: if the request is allowed to be sent
        :rtype: bool
    """
    def _base_url_allows(self, new_request: Node) -> bool:
        logger = get_logger(__name__)

        base_dict = self._crawler_seen_base[new_request.method]

        if new_request.url not in base_dict:
            base_dict[new_request.url] = 0
            return True
        else:
            base_dict[new_request.url] += 1
            if base_dict[new_request.url] == CRAWLER_PER_BASE_LIMIT:
                logger.warning("Base URL %s added to blocklist", new_request.url)
            
            if base_dict[new_request.url] >= CRAWLER_PER_BASE_LIMIT:
                return False

        return True

    def __iter__(self):
       return self

    """
        Get the next node to send a request.
        A new request must firstly pass the 
        blocked link criteria, and the per base url
        limit criteria.

        :return: the next request to sent
        :rtype: Node
    """
    def __next__(self):
        logger = get_logger(__name__)

        while len(self._crawler_unseen) != 0:
            new_request = self._crawler_unseen.pop()

            # store only the hash in the set
            # as the whole node is not needed
            self._crawler_seen_full.add(new_request.__hash__())

            if not self._blocklist_allows(new_request):
                continue

            if not self._base_url_allows(new_request):
                continue

            logger.info("Chosen an unvisited node")
            return new_request

        raise StopIteration