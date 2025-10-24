from html.parser import HTMLParser

name_informal = """ No \\n and < in attribute value """
description = """ Checks whether an attribute exits with the value containing a newline and less-than sign """

class DE2(HTMLParser):
    
    def __init__(self, *, convert_charrefs=True, debug=True):
        super().__init__(convert_charrefs=convert_charrefs)
        self._valid = True
        self._debug = debug

    def handle_starttag(self, tag, attrs):
        if not attrs:
            return
        for key, value in attrs:
            if not value: continue
            if "\n" in value and "<" in value:
                if self._debug:
                    print(f"Leak: {tag} {key}={value}")
                self._valid = False

    def is_valid(self):
        return self._valid

def run_rule(html, debug=False):
    de2 = DE2(debug=debug)
    de2.feed(html)
    res = de2.is_valid()
    del de2
    return res
