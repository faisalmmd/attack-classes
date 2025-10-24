from html.parser import HTMLParser

name_informal = """ Base Tags """
description = """  Checks whether the base tag is the first tag before an attribute taking URLs.
                    A base element, if it has an href attribute, must come before any other
                    elements in the tree that have attributes defined as taking URLs, except the html element. """

class DM5(HTMLParser):
    _state = "out_of_head"

    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)
        self._debug = debug
        self._state = "init"

    def handle_starttag(self, tag, attrs):
        attr_names = [k for k, _ in attrs]

        if self._debug and self._state != "error":
            print(f"{tag}: state {self._state} -> {attr_names}")
        if self._state == "init":
            if tag == "base" and "href" in attr_names:
                self._state = "base_exists"                
            elif "src" in attr_names or "href" in attr_names:
                self._state = "need_url_early"
        elif self._state == "need_url_early":
            if tag == "base" and "href" in attr_names:
                self._state = "error"  

    def is_valid(self):
        return self._state != "error"


def run_rule(html, debug=False):
    dm5_3 = DM5(debug=debug)
    dm5_3.feed(html)
    res = dm5_3.is_valid()
    del dm5_3
    return res
