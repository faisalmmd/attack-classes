from html.parser import HTMLParser

name_informal = """ Math """
description = """ Checks <math> for any disallowed element. """

class HF9_3(HTMLParser):
    
    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)
        self._debug = debug
        self._state = "html"
        self._text_integration_points = ["mi", "mo", "mn", "ms", "mtext"]
        self._html_integration_points = ["foreignobject", "desc", "title"]

        self._math_tags = ['math', 'maligngroup', 'malignmark', 'maction', 'menclose', 'merror', 'mfenced', 
        'mfrac', 'mglyph', 'mi', 'mlabeledtr', 'mlongdiv', 'mmultiscripts',
        'mn', 'mo', 'mover', 'mpadded', 'mphantom', 'mroot', 'mrow', 'ms', 'mscarriers', 
        'mscarry', 'msgroup', 'msline', 'mspace', 'msqrt', 'msrow', 'mstack', 'mstyle', 'msub',
        'msup', 'msubsup', 'mtable', 'mtd', 'mtext', 'mtr', 'munder', 'munderover', 'semantics', 'annotation', 'annotation-xml']

    def handle_starttag(self, tag, attrs):
        if self._state == "html":
            if tag == "math":
                self._state = "math"
            if tag == "svg":
                self._state = "svg"
            return

        if self._state == "math":
            if tag in self._text_integration_points:
                self._state = "html"
            if tag in "annotation-xml" and "encoding" in attrs:
                if attrs["encoding"] in ["text/html", "application/xhtml+xml"]:
                    self._state = "html" 
            if tag not in self._math_tags:
                if self._debug:
                    print(f"{tag} -> {attrs}")
                self._state = "error"          
            return

        if self._state == "svg":
            if tag in self._html_integration_points:
                self._state = "html"
            return            

    def handle_endtag(self, tag):
        if self._state == "html":
            if tag in self._html_integration_points:
                self._state = "svg"
            if tag in self._text_integration_points:
                self._state = "math"
            if tag == "annotation-xml":
                self._state = "math"
            return

        if self._state == "math" and tag == "math":
            self._state = "html"
            return

        if self._state == "svg" and tag == "svg":
            self._state = "html"
            return

    def is_valid(self):
        return self._state != "error"

def run_rule(html, debug=False):
    hf9_3 = HF9_3(debug=debug)
    hf9_3.feed(html)
    res = hf9_3.is_valid()
    del hf9_3
    return res
