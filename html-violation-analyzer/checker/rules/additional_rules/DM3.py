from html.parser import HTMLParser

name_informal = """ Srcdoc priority """
description = """ Checks whether an ifram element exists with both defined, src and srcdoc. """

class DM3(HTMLParser):

    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)
        self._valid = True
        self._debug = debug

    def handle_starttag(self, tag, attrs):
        if tag == "iframe":
            attr_names = [k for k, _ in attrs]
            if "src" in attr_names and "srcdoc" in attr_names:
                self._valid = False

    def is_valid(self):
        return self._valid


def run_rule(html, debug=False):
    dm3 = DM3(debug=debug)
    dm3.feed(html)
    res = dm3.is_valid()
    del dm3
    return res
