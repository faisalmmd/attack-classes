from html.parser import HTMLParser

name_informal = """ Invalid event handler """
description = """ Checks if all elements that use event handlers are allowed to use it. """

class EH3(HTMLParser):
    
    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)        
        self._valid = True
        self._debug = debug
        self._data = []
        self._element_allow_list = ['canvas', 'buttom', 'video', 'th', 'nav', 'em', 'cite', 'object', 'h4',
        'h2', 'dt', 'iframe', 'article', 'ul', 'h3', 'audio', 'source', 'table',
        'dd', 'figure', 'b', 'marquee', 'option', 'textarea', 'u', 'area', 'p',
        'label', 'body', 'script', 'i', 'button', 'select', 'meta', 'td', 'tr',
        'form', 'link', 'li', 'span', 'div', 'input', 'img', 'a']

    def handle_starttag(self, tag, attrs):
        for k, v in attrs:
            if k.startswith("on") and tag not in self._element_allow_list:
                if self._debug:
                    print(f"{tag} -> {attrs}")
                    print(k)
                self._valid = False
                self._data.append(tag)

    def get_data(self):
        return self._data

    def is_valid(self):
        return self._valid

def run_rule(html, debug=False):
    eh3_2 = EH3(debug=debug)
    eh3_2.feed(html)
    res = eh3_2.is_valid()
    # del eh3_2
    return res
