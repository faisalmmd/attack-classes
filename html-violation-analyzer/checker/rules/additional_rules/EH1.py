from html.parser import HTMLParser

name_informal = """ Invalid event handler """
description = """ Checks whether an element exists that uses an invalid event handler. """

class EH3(HTMLParser):
    
    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)        
        self._valid = True
        self._debug = debug
        self._data = []
        self._event_handler_allow_list = ['onwheel', 'ontouchmove', 'onbeforecopy', 'onbeforeunload', 'onselect',
       'oncut', 'onresize', 'onpropertychange', 'onscroll', 'onunload',
       'onfocusin', 'onwebkitspeechchange', 'oncopy', 'onfocusout',
       'ontouchend', 'onpaste', 'oninvalid', 'oninput', 'onselectstart',
       'onmouseup', 'ondragstart', 'onmouseleave', 'onmouseenter',
       'ondblclick', 'oncontextmenu', 'onmousemove', 'onkeydown', 'onkeyup',
       'ontouchstart', 'onkeypress', 'on', 'onmousedown', 'onsubmit',
       'onchange', 'onblur', 'onfocus', 'onerror', 'onload', 'onmouseout',
       'onmouseover', 'onclick']

    def handle_starttag(self, tag, attrs):
        for k, v in attrs:
            if k.startswith("on") and k not in self._event_handler_allow_list:
                if self._debug:
                    print(f"{tag} -> {attrs}")
                    print(k)
                self._valid = False
                self._data.append(k)

    def get_data(self):
        return self._data

    def is_valid(self):
        return self._valid

def run_rule(html, debug=False):
    eh3_1 = EH3(debug=debug)
    eh3_1.feed(html)
    res = eh3_1.is_valid()
    # del eh3_1
    return res
