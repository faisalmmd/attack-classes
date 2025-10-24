from html.parser import HTMLParser

name_informal = """ Non-terminated target """
description = """ Checks whether a target attribute exists that contains a newline. """

class DE6(HTMLParser):
    
    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)
        self._valid = True
        self._debug = debug

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if not value: continue
            if name == "target" and "\n" in value:
                if self._debug:
                    print(tag)
                    print(value)
                self._valid = False

    def is_valid(self):
        return self._valid


def run_rule(html, debug=False):
    de6 = DE6(debug=debug)
    de6.feed(html)
    res = de6.is_valid()
    del de6
    return res
