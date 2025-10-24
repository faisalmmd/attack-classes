from html.parser import HTMLParser

name_informal = """ Option that ends with EOF """
description = """ Checks whether an option element exists that remains unclosed. """

class DE4(HTMLParser):
    
    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)
        self._state = "fine"
        self._debug = debug

    def handle_starttag(self, tag, attrs):
        if tag == "option" and self._state == "fine":
            self._state = "error"

    def handle_endtag(self, tag):
        if tag == "option" and self._state == "error":
            self._state = "fine"

        if tag == "select" and self._state == "error":
            self._state = "fine"

        if tag == "datalist" and self._state == "error":
            self._state = "fine"

    def is_valid(self):
        return self._state != "error"

def run_rule(html, debug=False):
    de4 = DE4(debug=debug)
    de4.feed(html)
    res = de4.is_valid()
    del de4
    return res
