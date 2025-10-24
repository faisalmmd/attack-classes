from html.parser import HTMLParser

name_informal = """ Element Relationship """
description = """ Checks if an element related to form contains an id value that is not allowed """

class DC2(HTMLParser):

    def __init__(self, *, convert_charrefs=True, debug=False):
        super().__init__(convert_charrefs=convert_charrefs)        
        self._state = "init"
        self._debug = debug
        self._relation_elements = ["button","fieldset","image","img","input","object","output","select","textarea"]
        self._js_properties = ["0","acceptCharset","​action","​autocomplete","​enctype","​encoding","​method","​name","​noValidate","​target","​elements","​length","​checkValidity",
        "​reportValidity","​requestSubmit","​reset","​submit","​constructor","​title","​lang","​translate","​dir","​hidden","​accessKey","​draggable","​spellcheck","​autocapitalize",
        "​contentEditable","​isContentEditable","​inputMode","​offsetParent","​offsetTop","​offsetLeft","​offsetWidth","​offsetHeight","​style","​innerText","​outerText","​onbeforexrselect",
        "​onabort","​onblur","​oncancel","​oncanplay","​oncanplaythrough","​onchange","​onclick","​onclose","​oncontextmenu","​oncuechange","​ondblclick","​ondrag","​ondragend","​ondragenter",
        "​ondragleave","​ondragover","​ondragstart","​ondrop","​ondurationchange","​onemptied","​onended","​onerror","​onfocus","​onformdata","​oninput","​oninvalid","​onkeydown","​onkeypress",
        "​onkeyup","​onload","​onloadeddata","​onloadedmetadata","​onloadstart","​onmousedown","​onmouseenter","​onmouseleave","​onmousemove","​onmouseout","​onmouseover","​onmouseup",
        "​onmousewheel","​onpause","​onplay","​onplaying","​onprogress","​onratechange","​onreset","​onresize","​onscroll","​onseeked","​onseeking","​onselect","​onstalled","​onsubmit",
        "​onsuspend","​ontimeupdate","​ontoggle","​onvolumechange","​onwaiting","​onwebkitanimationend","​onwebkitanimationiteration","​onwebkitanimationstart","​onwebkittransitionend",
        "​onwheel","​onauxclick","​ongotpointercapture","​onlostpointercapture","​onpointerdown","​onpointermove","​onpointerup","​onpointercancel","​onpointerover","​onpointerout",
        "​onpointerenter","​onpointerleave","​onselectstart","​onselectionchange","​onanimationend","​onanimationiteration","​onanimationstart","​ontransitionrun","​ontransitionstart",
        "​ontransitionend","​ontransitioncancel","​oncopy","​oncut","​onpaste","​dataset","​nonce","​autofocus","​tabIndex","​attachInternals","​blur","​click","​focus","​enterKeyHint",
        "​virtualKeyboardPolicy","​onpointerrawupdate","​namespaceURI","​prefix","​localName","​tagName","​id","​className","​classList","​slot","​attributes","​shadowRoot","​part","​assignedSlot",
        "​innerHTML","​outerHTML","​scrollTop","​scrollLeft","​scrollWidth","​scrollHeight","​clientTop","​clientLeft","​clientWidth","​clientHeight","​attributeStyleMap","​onbeforecopy",
        "​onbeforecut","​onbeforepaste","​onsearch","​elementTiming","​onfullscreenchange","​onfullscreenerror","​onwebkitfullscreenchange","​onwebkitfullscreenerror","​children",
        "​firstElementChild","​lastElementChild","​childElementCount","​previousElementSibling","​nextElementSibling","​after","​animate","​append","​attachShadow","​before","​closest",
        "​computedStyleMap","​getAttribute","​getAttributeNS","​getAttributeNames","​getAttributeNode","​getAttributeNodeNS","​getBoundingClientRect","​getClientRects",
        "​getElementsByClassName","​getElementsByTagName","​getElementsByTagNameNS","​hasAttribute","​hasAttributeNS","​hasAttributes","​hasPointerCapture","​insertAdjacentElement",
        "​insertAdjacentHTML","​insertAdjacentText","​matches","​prepend","​querySelector","​querySelectorAll","​releasePointerCapture","​remove","​removeAttribute","​removeAttributeNS",
        "​removeAttributeNode","​replaceChildren","​replaceWith","​requestFullscreen","​requestPointerLock","​scroll","​scrollBy","​scrollIntoView","​scrollIntoViewIfNeeded","​scrollTo",
        "​setAttribute","​setAttributeNS","​setAttributeNode","​setAttributeNodeNS","​setPointerCapture","​toggleAttribute","​webkitMatchesSelector","​webkitRequestFullScreen",
        "​webkitRequestFullscreen","​ariaAtomic","​ariaAutoComplete","​ariaBusy","​ariaChecked","​ariaColCount","​ariaColIndex","​ariaColSpan","​ariaCurrent","​ariaDescription",
        "​ariaDisabled","​ariaExpanded","​ariaHasPopup","​ariaHidden","​ariaKeyShortcuts","​ariaLabel","​ariaLevel","​ariaLive","​ariaModal","​ariaMultiLine","​ariaMultiSelectable",
        "​ariaOrientation","​ariaPlaceholder","​ariaPosInSet","​ariaPressed","​ariaReadOnly","​ariaRelevant","​ariaRequired","​ariaRoleDescription","​ariaRowCount","ariaRowIndex",
        "ariaRowSpan","ariaSelected","ariaSetSize","ariaSort","ariaValueMax","ariaValueMin","ariaValueNow","ariaValueText","getAnimations","getInnerHTML","nodeType",
        "nodeName","baseURI","isConnected","ownerDocument","parentNode","parentElement","childNodes","firstChild","lastChild","previousSibling","nextSibling","nodeValue",
        "textContent","ELEMENT_NODE","ATTRIBUTE_NODE","TEXT_NODE","CDATA_SECTION_NODE","ENTITY_REFERENCE_NODE","ENTITY_NODE","PROCESSING_INSTRUCTION_NODE","COMMENT_NODE",
        "DOCUMENT_NODE","DOCUMENT_TYPE_NODE","DOCUMENT_FRAGMENT_NODE","NOTATION_NODE","DOCUMENT_POSITION_DISCONNECTED","DOCUMENT_POSITION_PRECEDING","DOCUMENT_POSITION_FOLLOWING",
        "DOCUMENT_POSITION_CONTAINS","DOCUMENT_POSITION_CONTAINED_BY","DOCUMENT_POSITION_IMPLEMENTATION_SPECIFIC","appendChild","cloneNode","compareDocumentPosition","contains",
        "getRootNode","hasChildNodes","insertBefore","isDefaultNamespace","isEqualNode","isSameNode","lookupNamespaceURI","lookupPrefix","normalize","removeChild","replaceChild",
        "addEventListener","dispatchEvent","removeEventListener","__defineGetter__","__defineSetter__","hasOwnProperty","__lookupGetter__","__lookupSetter__","isPrototypeOf",
        "propertyIsEnumerable","toString","valueOf","__proto__","toLocaleString"]

    def handle_starttag(self, tag, attrs):
        if tag == "form":
            if self._state == "init":
                self._state = "in_form"

        if tag in self._relation_elements and self._state == "in_form":
            for k,v in attrs:
                if k=="id" and v in self._js_properties:
                    if self._debug:
                        print(f"{tag} -> {attrs}")
                    self._state = "error"

    def handle_endtag(self, tag):
        if tag == "form" and self._state == "in_form":
            self._state = "init"

    def is_valid(self):
        return self._state != "error"


def run_rule(html, debug=False):
    dc2 = DC2(debug=debug)
    dc2.feed(html)
    res = dc2.is_valid()
    del dc2
    return res
