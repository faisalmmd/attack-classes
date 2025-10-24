from html.parser import HTMLParser
import os
import sqlite3

name_informal = """ Handler Checker """
description = """ This is not a rule. It only collects inline handler and their elements. """

DATABASE_NAME = "/home/florian/Documents/MA/crawler/handlerResult3.db"

class EventHandlerChecker(HTMLParser):
    _handler_list = []

    def handle_starttag(self, tag, attrs):
        for k, v in attrs:
            if k.startswith("on"):
                self._handler_list.append((tag, k))

    def get_list_of_handlers(self):
        return self._handler_list

def database_check():
    if os.path.exists(DATABASE_NAME):
        return

    con = sqlite3.connect(DATABASE_NAME)
    cur = con.cursor()

    # Create table
    cur.execute("""CREATE TABLE element (id INTEGER PRIMARY KEY, name text)""")
    cur.execute("""CREATE TABLE handler (id INTEGER PRIMARY KEY, name text)""")
    cur.execute("""CREATE TABLE element_handler_count (element_id integer, handler_id integer, count integer)""")

    con.commit()
    con.close()

def run_rule(html):
    database_check()
    checker = EventHandlerChecker()
    checker.feed(html)
    handlers = checker.get_list_of_handlers()
    con = sqlite3.connect(DATABASE_NAME, timeout=60)
    cur = con.cursor()
    for element, handler in handlers:
        handler_row = cur.execute(f"SELECT id FROM handler WHERE name = '{handler}'").fetchone()
        if handler_row == None:
            cur.execute("insert into handler (name) values (?);", [handler])
            handler_row = cur.execute(f"SELECT id FROM handler WHERE name = '{handler}'").fetchone()
        handler_id = handler_row[0]

        element_row = cur.execute(f"SELECT id FROM element WHERE name = '{element}'").fetchone()
        if element_row == None:
            cur.execute("insert into element (name) values (?);", [element])
            element_row = cur.execute(f"SELECT id FROM element WHERE name = '{element}'").fetchone()
        element_id = element_row[0]

        count_row = cur.execute(f"SELECT count FROM element_handler_count WHERE handler_id = {handler_id} and element_id = {element_id}").fetchone()
        if count_row == None:
            cur.execute("insert into element_handler_count (element_id, handler_id, count) values (?, ?, ?)", (element_id, handler_id, 1))
        else:
            new_count = count_row[0] + 1
            cur.execute(f"UPDATE element_handler_count SET count = {new_count} WHERE handler_id = {handler_id} and element_id = {element_id}")

    con.commit()
    con.close()

    return True
