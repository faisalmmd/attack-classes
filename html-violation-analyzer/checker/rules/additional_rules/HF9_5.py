from html.parser import HTMLParser

name_informal = """ Foreign Elements """
description = """ Checks if any foreign element exists in html context. """

class HF9_5(HTMLParser):
    
    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)
        self._debug = debug
        self._state = "html"
        self._title_type = ""
        self._text_integration_points = ["mi", "mo", "mn", "ms", "mtext"]
        self._html_integration_points = ["foreignobject", "desc", "title"]
        
        self._svg_tags = ['foreignobject', 'svg', 'animate', 'a', 'altglyph', 'altglyphdef', 'altglyphitem', 'animatecolor',
        'animatemotion', 'animatetransform', 'circle', 'clippath', 'color-profile', 'cursor', 'defs', 'desc', 'ellipse',
        'feblend', 'fecolormatrix', 'fecomponenttransfer', 'fecomposite', 'feconvolvematrix', 'fediffuselightings',
        'fedisplacementmap', 'fedistantlight', 'feflood', 'fefunca', 'fefuncb', 'fefuncg', 'fefuncr', 'fegaussianblur',
        'feimage', 'femerge', 'femergenode', 'femorphology', 'feoffset', 'fepointlight', 'fespecularlighting', 'fespotlight',
        'fetile', 'feturbulence', 'filter', 'font', 'font-face', 'font-face-format', 'font-face-name', 'font-face-src',
        'font-face-uri', 'g', 'glyph', 'glyphref', 'hkern', 'image', 'line', 'lineargradient',
        'marker', 'mask', 'metadata', 'missing-glyph', 'mpath', 'path', 'pattern', 'polygon', 'polyline', 'radialgradient',
        'rect', 'script', 'set', 'stop', 'style', 'switch', 'symbol', 'text', 'textpath', 'title', 'tref', 'tspan', 'use', 'view', 'vkern']

        self._math_tags = ['math', 'maligngroup', 'malignmark', 'maction', 'menclose', 'merror', 'mfenced', 
        'mfrac', 'mglyph', 'mi', 'mlabeledtr', 'mlongdiv', 'mmultiscripts',
        'mn', 'mo', 'mover', 'mpadded', 'mphantom', 'mroot', 'mrow', 'ms', 'mscarriers', 
        'mscarry', 'msgroup', 'msline', 'mspace', 'msqrt', 'msrow', 'mstack', 'mstyle', 'msub',
        'msup', 'msubsup', 'mtable', 'mtd', 'mtext', 'mtr', 'munder', 'munderover', 'semantics', 'annotation', 'annotation-xml']

        self._html_dup_tags = ['math', 'a','font','script','style','svg','title']

    def handle_starttag(self, tag, attrs):
        # print(f"{tag} open in {self._state}")
        if self._state == "html":
            if tag == "math":
                self._state = "math"
            if tag == "svg":
                self._state = "svg"
            if tag == "title":
                self._title_type = "html"
            if (tag in self._math_tags or tag in self._svg_tags) and tag not in self._html_dup_tags:
                if self._debug:
                    print(f"{tag} -> {attrs}")
                self._state = "error"
            return

        if self._state == "math":
            if tag in self._text_integration_points:
                self._state = "html"
            if tag in "annotation-xml" and "encoding" in attrs:
                if attrs["encoding"] in ["text/html", "application/xhtml+xml"]:
                    self._state = "html"           
            return

        if self._state == "svg":
            if tag in self._html_integration_points:
                self._state = "html"
            if tag == "title":
                self._title_type = "svg"
            return            

    def handle_endtag(self, tag):
        # print(f"{tag} close in {self._state}")
        if self._state == "html":
            # title has extra case, as it exists in html and svg
            if tag == "title" and self._title_type == "html":
                self._state = "html"
            elif tag in self._html_integration_points:
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
    hf9_5 = HF9_5(debug=debug)
    hf9_5.feed(html)
    res = hf9_5.is_valid()
    del hf9_5
    return res
