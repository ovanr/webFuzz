"""
    A Node stores the data describing a single request-response pair. 
"""
from __future__ import annotations

import jsonpickle

from typing           import Dict, List, Set, Iterator, Tuple, Any, Union
from urllib.parse     import urlparse, urlunparse
from kids.cache       import cache
from math             import log2, ceil
from aiohttp.typedefs import CIMultiDictProxy

from .environment   import env
from .misc          import object_to_tuple
from .types         import OutputMethod, Params, Policy, XSSConfidence, XssParams, HTTPMethod, Label, Bucket, FuzzerException, CFGTuple, Numeric, CFG

# post (and maybe get) parameters can get pretty huge. for instance when sending a file
# via post. Or sometimes a parameter can get reescaped in every request/response cycle
# making it grow infinitely long. This value crops all parameters to this max size in characters.
MAX_PARAMETER_SIZE = 1000

# for calculating the node rank
COVER_SCORE_RWEIGHT   =  0.40
MUTATED_SCORE_RWEIGHT =  0.10
SINK_SCORE_RWEIGHT    =  0.30
EXEC_TIME_RWEIGHT     = -0.30
NODE_SIZE_RWEIGHT     = -0.10
PICKED_SCORE_RWEIGHT  = -0.40


# for calculating the lightest node
EXEC_TIME_LWEIGHT = -0.60
NODE_SIZE_LWEIGHT = -0.30
UNCERTAINTY_THRESH = 0.1

"""
    Calculate the weighted difference between two numeric values
    Formula: (weight * (value2 - value1)) / (|value1 + value2| / 2)

    :return: the result of the calculation
    :rtype: float 
    """
def calc_weighted_difference(value1: Numeric, value2: Numeric, weight: float) -> float:
    their_sum = abs(value1 + value2) / 2
    return weight * (value1 - value2)/their_sum if their_sum > 0 else 0

def to_bucket(hit_count: int) -> Bucket:
    # 9 buckets: 1  2  3-4  5-8  9-16 17-32 33-64 65-128 129-255
    return ceil(log2(hit_count)) if hit_count < 256 else 8

def parse_headers(raw_headers: CIMultiDictProxy[str]) -> Iterator[Tuple[Label, str]]:
    relevant_headers = filter(lambda h: h[0].startswith("I-"), raw_headers.items())
    for name, value in relevant_headers:
        yield (int(name[2:]), value)

def parse_file(fileName: str) -> Iterator[Tuple[Label, str]]:
    with open(fileName, "r") as f:
        for line in f.readlines():
            if not line: continue
            line = line.replace("\n", "")

            label, _, value = line.partition('-')
            yield (int(label), value)

class Node:
    """
       Node constructor

       :param url: the url of the request
       :type url: str
       :param method: the http method, only "GET" or "POST" are supported so far
       :type method: HTTPMethod
       :param params: the GET and POST parameters
       :type params: Params
       :param cover_score_parent: the cover_score_xorof its parent node in case it is a mutated node
       :type cover_score_parent: int
       :param exec_time: time it took for the request to be completed in seconds
       :type param: float

       :return: the newly created Node
       :rtype: Node
    """
    def __init__(self,
                 url: str,
                 method: HTTPMethod,
                 params: Params = None,
                 parent_request: Union[Node,None] = None,
                 exec_time: float = 0):

        self._url = url
        self.method = method

        if not params:
            self.params = { HTTPMethod.GET: {}, HTTPMethod.POST: {} }
        else:
            self.params = params

        if method == HTTPMethod.GET and self.params[HTTPMethod.POST]:
            raise FuzzerException("Something went wrong. A GET request cannot have POST parameters")

        self.exec_time: float = exec_time

        # instrumentation related metadata
        self.cover_score_xor: int = 0  # coverage score (xor label count)
        self.cover_score_single: int = 0  # coverage score (simple label count)
        self.picked_score: int = 0  # how many times it has been chosen for further mutation
        self.parent_request = parent_request  # coverage score of the parent (node that we got mutated from)
        self.sinks = set()

        self.ref_count: int = 0
        self.xss_confidence = XSSConfidence(XSSConfidence.NONE)

    @cache(key=lambda node: (node._url))
    @property
    def url(self) -> str:
        if env.args.unique_anchors:
            return self._url
        else:
            return urlunparse(urlparse(self._url)._replace(fragment=''))
    
    @property
    def is_mutated(self) -> bool:
        return type(self.parent_request) != type(None)

    @property
    def sink_score(self) -> int:
        return len(self.sinks)

    @property
    def params(self) -> Params:
        return self._params

    def calculate_param_size(self):
        def calc_params_size(params: Dict[str, List[str]]) -> int:
               size = 0
               for k in params.keys():
                   psize = len(str(params[k]))
                   if psize > MAX_PARAMETER_SIZE:
                       params[k] = params[k][:MAX_PARAMETER_SIZE]
                       psize = MAX_PARAMETER_SIZE   
                   size += psize
               return size

        self.size = 0
        for location in self._params.keys():
            self.size += calc_params_size(self._params[location])

    @params.setter
    def params(self, new_value: Params) -> Node:
        self._params = new_value
        self.calculate_param_size()

        return self

    @property
    def cover_score(self):
        if env.instrument_args.policy == Policy.EDGE:
            score = self.cover_score_xor
            count = env.instrument_args.edges
        else:
            score = self.cover_score_single
            count = env.instrument_args.basic_blocks

        return 100*score / count

    @property
    def cover_score_raw(self):
        if env.instrument_args.policy == Policy.NODE:
            return self.cover_score_single
        else:
            return self.cover_score_xor

    @property
    def mutated_score(self) -> int:
        if type(self.parent_request) == type(None):
            return 0

        return self.cover_score_raw - self.parent_request.cover_score_raw

    """
       Parses the instrumentation feedback from a request. 

       :param worker_id: the request ID as sent to web app using header REQ-ID
       :type worker_id: str
       :param headers: the http headers of the response
       :type headers: Dict[str, str]

       :return: Named tuple containing the CFG for the XOR and Single Basic Block methods
       :rtype: CFGTuple
    """
    def parse_instrumentation(self, 
                              headers: CIMultiDictProxy[str],
                              worker_id: str = "") -> CFGTuple:
        cfg_xor: CFG = {}
        cfg_single: CFG = {}
        instrument_args = env.instrument_args
        
        iterator = None
        if instrument_args.output_method == OutputMethod.HTTP:
            iterator = parse_headers(headers)

        elif instrument_args.output_method == OutputMethod.FILE:
            iterator = parse_file("/var/instr/map." + worker_id)

        if instrument_args.policy == Policy.EDGE or \
           instrument_args.policy == Policy.NODE:
            cfg: CFG = {}
            for (label, hit_count) in iterator:
                cfg[label] = to_bucket(int(hit_count))

            if instrument_args.policy == Policy.EDGE:
                cfg_xor = cfg
            else:
                cfg_single = cfg

        elif instrument_args.policy == Policy.NODE_EDGE:
            for (label, value) in iterator:
                (xor, single) = map(int, value.split('-'))
                if xor > 0:
                    cfg_xor[label] = to_bucket(xor)
                if single > 0:
                    cfg_single[label] = to_bucket(single)

        self.cover_score_xor = len(cfg_xor)
        self.cover_score_single = len(cfg_single)

        return CFGTuple(xor_cfg=cfg_xor,
                        single_cfg=cfg_single)

    """
        Defines the ordering of any two nodes (used in sort(), bisect.insort(), heapq.heappush())
        Because we use a min-heap in NodeIterator, a smaller node will actually have higher priority
        in the heap tree. Thus in this ordering smaller nodes are more favorable

        :param node2: the node to compare with
        :type node2: Node
        :return: if self < node2 then <0, if self == node2 then 0, if self > node2 then >0
        :rtype: float
    """
    def __cmp__(self, node2: Node) -> float:
        if not isinstance(node2, type(self)):
            raise NotImplementedError()

        return calc_weighted_difference(node2.cover_score_raw,      self.cover_score_raw,      COVER_SCORE_RWEIGHT)    + \
               calc_weighted_difference(node2.exec_time,            self.exec_time,            EXEC_TIME_RWEIGHT)      + \
               calc_weighted_difference(node2.size,                 self.size,                 NODE_SIZE_RWEIGHT)      + \
               calc_weighted_difference(node2.picked_score,         self.picked_score,         PICKED_SCORE_RWEIGHT)   + \
               calc_weighted_difference(node2.mutated_score,        self.mutated_score,        MUTATED_SCORE_RWEIGHT)  + \
               calc_weighted_difference(node2.sink_score,           self.sink_score,           SINK_SCORE_RWEIGHT)
        
    def __lt__(self, node2: Node) -> bool:
        return self.__cmp__(node2) < 0

    def __gt__(self, node2: Node) -> bool:
        return self.__cmp__(node2) > 0

    """
        Returns whether Self Node is 'lighter' than node2 Node.
        Lighter means has lower execution time and/or smaller parameter size.
        A weighted difference is calculated using these two measurements.

        :param node2: the node to compare with
        :type node2: Node
        :return: if self is lighterThan node2
        :rtype: bool 
    """
    def is_lighter_than(self, node2: Node) -> bool:
        if not isinstance(node2, type(self)):
            raise NotImplementedError()

        weighted_diff = calc_weighted_difference(node2.exec_time, self.exec_time,   EXEC_TIME_LWEIGHT) + \
                        calc_weighted_difference(node2.size,      self.size,        NODE_SIZE_LWEIGHT)

        is_lighter_than_node2: bool = weighted_diff < 0

        # if self is lighter than node2 then
        # it will be replaced with node2 in global map
        # since replacing nodes is expensive and response time
        # can vary to some degree, we provide the UNCERTAINTY_THRESH
        # to guard against that (i.e. only if self node is significantly lighter than node2)
        if is_lighter_than_node2 and abs(weighted_diff) < UNCERTAINTY_THRESH:
            return False
        
        return is_lighter_than_node2

    """
        The hash of the node's parameters. 

        :return: the hash of the params
        :rtype: int
    """
    @cache(key=lambda node: (object_to_tuple(node.params)))
    @property
    def _params_hash(self) -> int:
        return hash(object_to_tuple(self.params))

    """
        The hash of the node. (Needed in order for Node to be part of a Set)
        It is made from the immutable (not enforced) parts of the node.

        :return: the hash of the node
        :rtype: int
    """
    @cache(key=lambda node: (node.method, node.url, node._params_hash))
    def __hash__(self) -> int:
        return hash((self.url, self.method, self._params_hash))

    """
        The json format of the node. Note that not all the Node's attributes
        are outputted to the json. See Node.__getstate__

        :return: the json format of the node
        :rtype: str
    """
    @cache(key=lambda node: (node.method, node.url, node._params_hash, node.xss_confidence))
    def json(self) -> str:
        return jsonpickle.encode(self, unpicklable=False)

    """
        Tell jsonpickle which attributes from the Node
        to output to the final json

        :return: the selected few attributes
        :rtype: Dict[str, Any]
    """
    def __getstate__(self) -> Dict[str, Any]:
        # tells jsonpickle to serialize
        # only certain class attributes

        state = self.__dict__.copy()

        state['method'] = self.method.name
        state['xss_confidence'] = self.xss_confidence.name
        state['cover_score'] = self.cover_score
        state['mutated_score'] = self.mutated_score
        state['hash'] = self.__hash__()

        if 'json' in state:
            del state['json']

        del state['picked_score']
        del state['ref_count']
        del state['cover_score_single']
        del state['cover_score_xor']
        del state['parent_request']

        return state

    """
        Compare if equal. (Needed in order for Node to be part of a Set)
        Uses their hash.

        :param node2: the node to compare with
        :type node2: Node
        :return: self == node2
        :rtype: bool
    """
    def __eq__(self, node2: Node) -> bool:
        if not isinstance(node2, type(self)): 
            raise NotImplementedError()

        return self.__hash__() == node2.__hash__()

    """
        Defines the printable format of a node

        :return: the string representation of the node
        :rtype: str 
    """
    def __str__(self) -> str:
        return self.json()
        
    """
        Defines the Python-like string format of the node
        TODO: Create an Python-acceptable string format of the Node
              instead of calling self.__str__()

        :return: the string representation of the node
        :rtype: str 
    """
    def __repr__(self) -> str:
        return self.__str__()