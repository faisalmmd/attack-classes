from html.parser import HTMLParser

name_informal = """ Move element from head to body """
description = """ Checks the head section of the document. The rule checks if any head element appears as attribute. """

class HF1_2(HTMLParser):

    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)
        self._state = "init"
        self._allow_list = ["base", "basefont", "bgsound",
            "link", "meta", "title", "noscript", "script",
            "noframes", "style"]
        self._debug = debug

    def handle_starttag(self, tag, attrs):
        if self._state == "init" and tag == "head":
            self._state = "in_head"
        elif self._state == "in_head":
            if not attrs:
                return
            for key, value in attrs:
                for e in self._allow_list:
                    if "<" + e in key:
                        self._state = "error"
                    if value and "<" + e in value:
                        self._state = "error"
            if self._state == "error" and self._debug:
                print(f"{tag} -> {attrs}")

    def handle_endtag(self, tag):
        if self._state == "in_head" and tag == "head":
            self._state = "close"    

    def is_valid(self):
        return self._state != "error"


def run_rule(html, debug=False):
    hf1_2 = HF1_2(debug=debug)
    hf1_2.feed(html)
    res = hf1_2.is_valid()
    del hf1_2
    return res
