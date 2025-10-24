from html.parser import HTMLParser

name_informal = """ Option that contains another option """
description = """ Checks whether an option element exits that contains another option element """

class DE4(HTMLParser):
    
    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)
        self._state = "fine"
        self._debug = debug

    def handle_starttag(self, tag, attrs):
        if tag == "option":
            if self._state == "fine":
                self._state = "open"
            elif self._state == "open":
                self._state = "error"

    def handle_endtag(self, tag):
        if tag == "option" and self._state == "open":
            self._state = "fine"

    def is_valid(self):
        return self._state != "error"

def run_rule(html, debug=False):
    de4_2 = DE4(debug=debug)
    de4_2.feed(html)
    res = de4_2.is_valid()
    del de4_2
    return res
