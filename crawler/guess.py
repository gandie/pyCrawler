# -*- coding: utf-8 -*-
#
# guess.py - helper module of pyCrawler to evaluate JS, Python and JSON
# received from crawler in order to extract more urls
#
# Copyright (c) 2019 Lars Bergmann
#
# GNU GENERAL PUBLIC LICENSE
#    Version 3, 29 June 2007
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# JS parser
from slimit import ast
from slimit.parser import Parser
from slimit.visitors import nodevisitor

# guess language of unknown content
from guesslang import Guess

# CUSTOM
import crawler.logfacility as logfacility

LOGGER = logfacility.get_logger()


def scan_js(crawler, url, content):
    '''
    scan javascript for url assignments (like ajax calls).
    '''
    LOGGER.info('Scanning Javascript on %s' % url)

    parser = Parser()
    tree = parser.parse(content)
    for node in nodevisitor.visit(tree):
        if not isinstance(node, ast.Assign):  # <something>: <something>
            continue
        leftval = getattr(node.left, 'value', '')  # 'leftval': <something>
        if not leftval:
            continue
        if 'url' not in leftval:  # 'url': <something>
            continue
        if isinstance(node.right, ast.String):  # 'url': 'somestring'
            LOGGER.info(
                'Found interesting url in JS: %s' % node.right.value[1:-1]
            )
            crawler.check_link(url, node.right.value[2:-1])
        for item in node.right.__dict__.values():  # string in <something>
            # <something> may be function_call() / variable + 'somestring'
            if isinstance(item, ast.String):
                LOGGER.info(
                    'Found interesting url in JS: %s' % item.value[1:-1]
                )
                crawler.check_link(url, item.value[2:-1])


def scan_plain(crawler, url, text):
    '''CPUTASK
    scan text/plain content to be a known language. try to evaluate if
    known language is found check for more urls'''

    LOGGER.info('Checking plain text content from url: %s' % url)
    langnames = Guess().probable_languages(text)
    LOGGER.info('Guessed langnames from url: %s %s' % (url, langnames))
    if 'Javascript' in langnames:
        try:
            json_from_plain = json.loads(text)
        except Exception:  # we dont care too much
            json_from_plain = None
            LOGGER.error('JSON evaluation failed on : %s' % text)
        if json_from_plain:
            LOGGER.info('Got JSON from plain: %s' % json_from_plain)

    if 'Python' in langnames:
        try:
            # python_fom_plain = eval(text)
            python_fom_plain = builtin_ast.literal_eval(text)
        except Exception:  # we dont care too much
            LOGGER.error('Python evaluation failed on : %s' % text)
            python_fom_plain = None
        if python_fom_plain:
            LOGGER.info('Got Python from plain: %s' % python_fom_plain)
            if isinstance(python_fom_plain, dict):
                urls = list(nested_find('url', python_fom_plain))
                LOGGER.info('Got urls from python dict: %s' % urls)
                for link in urls:
                    crawler.check_link(url, link)


def nested_find(self, key, dictionary):
    '''check nested dictionary for key, yield values. stolen from net'''
    for k, v in dictionary.items():
        if k == key:
            yield v
        elif isinstance(v, dict):
            for result in self.find(key, v):
                yield result
        elif isinstance(v, list):
            for d in v:
                for result in self.find(key, d):
                    yield result
