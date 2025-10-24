from html.parser import HTMLParser

name_informal = """ Noscript  """
description = """ Looks for the appearence of the string "</noscript" in noscript elements """

class HF7(HTMLParser):

    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)
        self._state = "init"
        self._debug = debug
        self._prev_element = None

    def handle_starttag(self, tag, attrs):
        if self._state == "init" and tag == "noscript":
            self._state = "in_noscript"        

        if self._state == "in_noscript" and tag != "noscript":
            for _, value in attrs:
                if value and "</noscript" in value:
                    if self._debug:
                        print("ELE")
                        print(f"{tag} -> {attrs}")
                    self._state = "error"

    def handle_endtag(self, tag):
        if self._state == "in_noscript" and tag == "noscript":
            self._state = "init"

    def handle_data(self, data):
        if self._state == "in_noscript" and "</noscript" in data:
            if self._debug:
                print("DATA")
                print(data)
            self._state = "error"

    def handle_comment(self, data):
        if self._state == "in_noscript" and "</noscript" in data:
            if self._debug:
                print("COMMENT")
                print(data)
            self._state = "error"

    def is_valid(self):
        return self._state != "error"

def run_rule(html, debug=False):
    hf7 = HF7(debug=debug)
    hf7.feed(html)
    res = hf7.is_valid()
    del hf7
    return res
