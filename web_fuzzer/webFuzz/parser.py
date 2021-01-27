

from urllib.parse import ParseResult, urlparse, urlunparse, parse_qs, urlencode, ParseResult
from bs4          import BeautifulSoup
from typing       import Set, List, Dict, Union,Tuple

from .misc        import get_logger
from .types       import HTTPMethod
from .node        import Node

Urllib_Url = ParseResult

class Parser:
    def __init__(self):
        pass

    def parse(self, node: Node, soup: BeautifulSoup) -> Set[Node]:        
        form_links = Parser.parse_forms(soup, node)
        a_links = Parser.parse_a_links(soup, node)

        return a_links.union(form_links)

    @staticmethod
    def parse_a_links(html: BeautifulSoup, from_node: Node) -> Set[Node]:
        """
        Extract href links(queries) and their parameters.

        :return: All links found in an HTML page which are extracted from href
        fields in anchor tags.
        :rtype: set
        """
        logger = get_logger(__name__)
        logger.debug("==> Extracting <a> links from html")

        links: Set[Node] = set()  # A set that contains all links found in the form of nodes.

        for anchor in html.findAll('a'):  # Search for all anchor elements.
            logger.debug("==> link parsing: %s", anchor.get('href'))

            result: Union[Urllib_Url, None] = Parser.parse_url(urlparse(anchor.get('href')), from_node)  # Parse href link found.
            if result is None:  # Skip empty href links found.
                continue
            url_obj: Urllib_Url = result

            # Parse a query string to dict of its parameters.
            params:Dict[str, List[str]] = parse_qs(url_obj.query, keep_blank_values=True)

            # Convert the url object back to string but without the query.
            url_base: str = urlunparse(url_obj._replace(query=''))

            links.add(Node(url=url_base,
                           method=HTTPMethod.GET,
                           params={HTTPMethod.GET: params, HTTPMethod.POST: {}}))

        logger.debug("==> got new links: %s", links)
        return links

    @staticmethod
    def parse_forms(html: BeautifulSoup, from_node: Node) -> Set[Node]:
        """
        Extract action, method and input fields from HTML forms.

        :return: All links found in an HTML page which are extracted from forms.
        :rtype: set
        """
        logger = get_logger(__name__)
        logger.debug("==> Extracting data from forms")

        links: Set[Node] = set()  # A set that contains all links found in the forms.

        for form_found in html.findAll('form'):
            logger.debug("==> Form parsing: %s", form_found)

            url_obj = Parser.parse_form_action(form_found.get('action'), from_node)
            if url_obj is None:
                continue

            # Parse a query string given as a string argument. Data returned as a dict.
            get_params: Dict[str, List[str]] = parse_qs(url_obj.query, keep_blank_values=True)

            # Convert the url object back to string but without the query.
            url: str = urlunparse(url_obj._replace(query=''))

            # Input element extraction from form found and processing.
            selects: Dict[str, List[str]] = Parser.parse_html_inputs(form_found.findAll('select'))
            inputs: Dict[str, List[str]] = Parser.parse_html_inputs(form_found.findAll('input'))
            textareas: Dict[str, List[str]] = Parser.parse_html_inputs(form_found.findAll('textarea'))

            body_params = selects | inputs | textareas

            # Method extraction from form.
            method: HTTPMethod = Parser.parse_form_method(form_found.get('method'))
            if method == HTTPMethod.GET:
                get_params.update(body_params)
                body_params = {}

            logger.debug("==> Form get: %s", get_params)
            logger.debug("==> Form post: %s", body_params)

            links.add(Node(url=url,
                           method=method,
                           params={HTTPMethod.GET: get_params, HTTPMethod.POST: body_params}))

        logger.debug("==> Got new links: %s", links)
        return links

    @staticmethod
    def un_type(parameter:str) -> str:
        """
        Transforms query/post parameter from oranges[] to oranges.
        """
        if parameter[-2:] == "[]":  # Check if the last two chars are [].
            return parameter[:-2]
        else:
            return parameter

    @staticmethod
    def relative_to_absolute(base_url:Urllib_Url, relative_url:Urllib_Url) -> Urllib_Url:
        """
        Converts a relative url to an absolute.
        e.g. href="action.php" called from http://param_typealhost/api/login.php
        should be: http://param_typealhost/api/action.php
        """
        if not base_url.path:
            return relative_url._replace(path="/" + relative_url.path)
        else:
            return relative_url._replace(path=base_url.path[0:base_url.path.rfind("/")] + "/" + relative_url.path)

    @staticmethod
    def set_default_query(base_node: Node, target_url: Urllib_Url) -> Urllib_Url:
        """
        Replace query field of url_obj with the query string of the self.node.
        Essentially it returns the same address of self.node).
        """
        node_query = urlencode(base_node.params[HTTPMethod.GET], doseq=True)
        return target_url._replace(query=node_query)

    @staticmethod
    def set_default_path(base_node: Node, target_url: Urllib_Url) -> Urllib_Url:
        """
        Replace url_obj path with the path of calling node.
        """
        return target_url._replace(path=urlparse(base_node.url).path)

    @staticmethod
    def set_default_hostname(base_url: Urllib_Url, target_url: Urllib_Url) -> Urllib_Url:
        """
        Set the netloc and scheme of target_url as that of base_url
        """
        return target_url._replace(scheme=base_url.scheme, netloc=base_url.netloc)

    @staticmethod
    def parse_html_inputs(inputs: List) -> Dict[str, List[str]]:
        result: Dict[str, List[str]] = {}

        for html_input in inputs:
            name: Union[str, None] = html_input.get('name')

            if name is None:
                continue  # Skip this input element if name field is missing.

            value: str = html_input.get('value', '')
            if not value:
                # if no value present, search in child <option> elements
                option = html_input.find('option')
                if option:
                    value: str = option.get('value', '')

            if name in result:  # Check if the same name already exists in input dictionary.
                result[name].append(value)
            else:
                result[name] = [value]

        return result

    @staticmethod
    def parse_form_method(method: Union[str, None]) -> HTTPMethod:
        if not method or method.upper() == "GET":
            return HTTPMethod.GET
        else:
            return HTTPMethod.POST

    @staticmethod
    def parse_form_action(action: Union[str, None], from_node: Node) -> Union[Urllib_Url, None]:
        if action is None:  # Form has no action field.
            # use action from the url that contains this form
            return urlparse(from_node.url)
        else:
            return Parser.parse_url(urlparse(action), from_node)

    @staticmethod
    def parse_url(url: Urllib_Url, from_node: Node) -> Union[Urllib_Url, None]:
        """
        Fixes a URL object as returned from urllib.parse.urlparse.
        It will try to turn it to an absolute url.
        :param url_obj: URL 6-item tuple containing all its subfields as returned from urllib.parse.urlparse
        :type url_obj: 6-item tuple: (scheme, netloc, path, params, query, fragment)
        :return: The url_obj or None if url is of different domain
        :rtype: None|type(url_obj)
        """
        
        from_url: Urllib_Url = urlparse(from_node.url)  # Get the URL of the calling node.

        if url.netloc == '':  # Link does not have a domain name.

            if url.path and url.path[0] != "/":
                url = Parser.relative_to_absolute(from_url, url)

            elif not url.path:  # Link points to the same URL the request was made.
                # Fixes path to point to that.
                # e.g. href="#", href="", href="?hey=there"
                if not url.query:  # No query string is given.
                    url = Parser.set_default_query(from_node, url)
                url = Parser.set_default_path(from_node, url)

            url = Parser.set_default_hostname(from_url, url)

        elif from_url.netloc != url.netloc:
            # Not in the same fully qualified domain name (FQDN) so it skips it.
            # TODO: whether to skip this should be based on a flag ?!
            return None

        return url
