from html.parser import HTMLParser

name_informal = """ Base Tags """
description = """ Checks whether a base tag exists that is outside the head section. """

class DM5(HTMLParser):

    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)
        self._state = "init"
        self._debug = debug

    def handle_starttag(self, tag, attrs):
        if tag == "head":
            self._state = "open"

        if tag == "base" and self._state != "open":
            if self._debug:
                print(f"base -> {attrs}")
            self._state = "error"

    def handle_endtag(self, tag):
        if tag == "head" and self._state == "open":
            self._state = "close"

    def is_valid(self):
        return self._state != "error"


def run_rule(html, debug=False):
    dm5_1 = DM5(debug=debug)
    dm5_1.feed(html)
    res = dm5_1.is_valid()
    del dm5_1
    return res
