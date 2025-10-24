from html.parser import HTMLParser

name_informal = """ Textarea that ends with EOF """
description = """ Checks whether a textarea exists that remains unclosed. """

class DE3(HTMLParser):
    
    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)
        self._state = "fine"
        self._debug = debug

    def handle_starttag(self, tag, attrs):
        if tag == "textarea" and self._state == "fine":
            self._state = "error"

    def handle_endtag(self, tag):
        if tag == "textarea" and self._state == "error":
            self._state = "fine"

    def is_valid(self):
        return self._state != "error"

def run_rule(html, debug=False):
    de3 = DE3(debug=debug)
    de3.feed(html)
    res = de3.is_valid()
    del de3
    return res
