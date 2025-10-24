from html.parser import HTMLParser

name_informal = """ Multiple same attributes """
description = """ Checks whether an element exists with multiple attributes having the same name. """

class DM2(HTMLParser):

    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)
        self._valid = True
        self._debug = debug

    def handle_starttag(self, tag, attrs):
        names = [name for name, _ in attrs]
        if len(names) != len(set(names)):
            if self._debug:
                print(tag)
                print(attrs)
                names.sort()
                print(names)
            self._valid = False

    def is_valid(self):
        return self._valid

def run_rule(html, debug=False):
    dm2 = DM2(debug=debug)
    dm2.feed(html)
    res = dm2.is_valid()
    del dm2
    return res
