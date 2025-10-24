from html.parser import HTMLParser

name_informal = """ Textarea that contains another textarea """
description = """ Checks whether a textarea contains another textarea. """

class DE3(HTMLParser):
    
    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)
        self._state = "fine"
        self._debug = debug

    def handle_starttag(self, tag, attrs):
        if tag == "textarea":
            if self._state == "fine":
                self._state = "open"
            elif self._state == "open":
                self._state = "error"

    def handle_endtag(self, tag):
        if tag == "textarea" and self._state == "open":
            self._state = "fine"

    def is_valid(self):
        return self._state != "error"

def run_rule(html, debug=False):
    de3_2 = DE3(debug=debug)
    de3_2.feed(html)
    res = de3_2.is_valid()
    del de3_2
    return res
