from html.parser import HTMLParser

name_informal = """ Meta Tags """
description = """ Checks whether a meta tag with http-equiv exists that is outside the head section. """

class DM4(HTMLParser):

    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)
        self._state = "init"
        self._debug = debug

    def handle_starttag(self, tag, attrs):
        if tag == "head":
            self._state = "open"

        if (tag == "meta" and self._state != "open" and
            "http-equiv" in [k for k, _ in attrs]):
            self._state = "error"
            if self._debug:
                print(tag)
                print(attrs)

    def handle_endtag(self, tag):
        if tag == "head" and self._state == "open":
            self._state = "close"

    def is_valid(self):
        return self._state != "error"


def run_rule(html, debug=False):
    dm4 = DM4(debug=debug)
    dm4.feed(html)
    res = dm4.is_valid()
    del dm4
    return res
