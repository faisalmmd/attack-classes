from html.parser import HTMLParser

name_informal = """ No <script in attribute name or value """
description = """ Checks whether an attribute exits with the name or value containing <script """

class DE2_2(HTMLParser):
    
    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)
        self._valid = True
        self._debug = debug

    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if "<script" in key:
                self._valid = False
                if self._debug:
                    print(f"Leak: {tag} {key}={value}")
            if value and "<script" in value:
                self._valid = False
                if self._debug:
                    print(f"Leak: {tag} {key}={value}")

    def is_valid(self):
        return self._valid

def run_rule(html, debug=False):
    de2_2 = DE2_2(debug=debug)
    de2_2.feed(html)
    res = de2_2.is_valid()
    del de2_2
    return res
