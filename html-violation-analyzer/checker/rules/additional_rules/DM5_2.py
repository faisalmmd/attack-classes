from html.parser import HTMLParser

name_informal = """ Base Tags """
description = """ Checks if more than one base tags exist """

class DM5(HTMLParser):

    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)
        self._base_tag_count = 0
        self._debug = debug

    def handle_starttag(self, tag, attrs):
        if tag == "base":
            self._base_tag_count += 1
            if self._debug:
                print(f"base -> {attrs}")

    def is_valid(self):
        return self._base_tag_count <= 1


def run_rule(html, debug=False):
    dm5_2 = DM5(debug=debug)
    dm5_2.feed(html)
    res = dm5_2.is_valid()
    del dm5_2
    return res