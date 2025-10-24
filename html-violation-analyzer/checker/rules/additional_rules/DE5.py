from html.parser import HTMLParser

name_informal = """ Form that contains another form """
description = """ Checks whether a form element exists that contains another form element """ 

class DE5(HTMLParser):
    
    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)
        self._state = "fine"
        self._debug = debug

    def handle_starttag(self, tag, attrs):
        if tag == "form":
            if self._state == "fine":
                self._state = "open"
            elif self._state == "open":
                self._state = "error"
                if self._debug:
                    print(tag)
                    print(attrs)

    def handle_endtag(self, tag):
        if tag == "form" and self._state == "open":
            self._state = "fine"

    def is_valid(self):
        return self._state != "error"

def run_rule(html, debug=False):
    de5 = DE5(debug=debug)
    de5.feed(html)
    res = de5.is_valid()
    del de5
    return res
