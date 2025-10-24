from html.parser import HTMLParser

name_informal = """ Nonce and event handler """
description = """ Checks whether an element exists that defines a nonce and an event handler. """

class EH3(HTMLParser):
    
    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)        
        self._valid = True
        self._debug = debug

    def handle_starttag(self, tag, attrs):
        e, n = False, False
        for k, v in attrs:
            if k.startswith("on"): e = True
            if k == "nonce": n = True
        if e and n:
            if self._debug:
                print(f"{tag} -> {attrs}")
            self._valid = False

    def is_valid(self):
        return self._valid

def run_rule(html, debug=False):
    eh3 = EH3(debug=debug)
    eh3.feed(html)
    res = eh3.is_valid()
    del eh3
    return res
