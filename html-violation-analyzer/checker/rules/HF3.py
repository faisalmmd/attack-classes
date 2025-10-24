from html.parser import HTMLParser

name_informal = """ Modify body attributes """
description = """ Checks if two opening body tags exist. """

class HF3(HTMLParser):

    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)
        self._body_tag_count = 0
        self._debug = debug

    def handle_starttag(self, tag, attrs):
        if tag == "body":
            if self._debug:
                print(f"{tag} -> {attrs}")
            self._body_tag_count += 1

    def is_valid(self):
        return self._body_tag_count <= 1


def run_rule(html, debug=False):
    hf3 = HF3(debug=debug)
    hf3.feed(html)
    res = hf3.is_valid()
    del hf3
    return res
