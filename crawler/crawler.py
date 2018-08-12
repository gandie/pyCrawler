# -*- coding: utf-8 -*-
#
# crawler.py - main module of pyCrawler containing thread worker and crawler
#
# Copyright (c) 2017 Lars Bergmann
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

# pip
import requests
from lxml import etree

from slimit import ast
from slimit.parser import Parser
from slimit.visitors import nodevisitor

# builtin
import threading
#import Queue
from queue import Queue
import re
try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse
import random
#from StringIO import StringIO
from io import StringIO
from io import BytesIO
import time
from builtins import str
import js2py
import json

from guesslang import Guess

# CUSTOM
try:
    import logfacility
except ImportError:
    import crawler.logfacility as logfacility

# module settings
THREAD_TIMEOUT = 20
REQUEST_CON_TIMEOUT = 10
REQUEST_READ_TIMEOUT = 10
REQUEST_TIMEOUT = (REQUEST_CON_TIMEOUT, REQUEST_READ_TIMEOUT)
LOGGER = logfacility.build_logger()


class Worker(threading.Thread):
    '''
    Worker thread started by Crawler.crawl() method
    Fetches urls from inputQue and puts mail addresses found to mailQue and new
    links to resultQue.
    '''
    def __init__(self, inputQue, resultQue, mailQue, host, regex, keyword,
                 release, checkJS=False, **kwargs):

        super(Worker, self).__init__(**kwargs)

        self.inputQue = inputQue
        self.resultQue = resultQue
        self.mailQue = mailQue

        self.host = host
        self.release = release
        self.checkJS = checkJS
        self.keyword = keyword
        self.regex = regex

        self.base = None

        self.bytes_done = 0

        self.parser = etree.HTMLParser()

        self.bad_endings = [
            'pdf', 'jpg', 'mp4', 'zip', 'tif', 'png', 'svg', 'jpg', 'exe',
            'ico', 'css'  # we're not interested in css, for now...
        ]
        self.bad_words = [
            'facebook', 'twitter', 'youtube', 'microsoft', 'google',
            'wikipedia', 'amazon', 'github', 'jquery', 'bootstrap'
        ]
        self.tag_map = {
            'a': 'href',
            'area': 'href',
            'base': 'href',
            'link': 'href',
            'frame': 'src',
            'iframe': 'src',
            'base': 'href,'
        }

        if self.checkJS:
            self.tag_map.update({
                'script': 'src',
            })

    def extract_host(self, url):
        if self.host in url:
            return self.host
        return urlparse.urlparse(url).netloc

    def extract_links(self, html):
        '''
        build tree object from html and yield attributes from tags defined via
        tag_map. also filters bad_words and bad_endings
        '''
        # we need something that behaves like a filehandle here!
        # stringio = StringIO(html)
        stringio = BytesIO(html)
        try:
            tree = etree.parse(stringio, self.parser)
        except Exception as e:
            LOGGER.warning(e)
            LOGGER.warning('Eierau')
            return  # abort if we got invalid stuff
        for element in tree.iter():
            if element.tag not in self.tag_map:
                continue
            href = element.get(self.tag_map[element.tag])
            # print(href, element.tag)
            if not href:
                continue
            if href.split('.')[-1] in self.bad_endings:
                continue
            for bad_word in self.bad_words:
                if bad_word in href:
                    break
            else:  # read else like "nobreak"
                if element.tag == 'base':
                    self.base = href
                yield href

    def scan_js(self, url, content):
        '''scan javascript for url assignments (like ajax calls)'''
        # TODO: needs a queue!
        LOGGER.info('Scanning Javascript on %s' % url)
        # cut of last part from url
        # url = url.rsplit('/', 1)[0]

        parser = Parser()
        tree = parser.parse(content)
        for node in nodevisitor.visit(tree):
            if not isinstance(node, ast.Assign):
                continue
            leftval = getattr(node.left, 'value', '')
            if not leftval:
                continue
            if 'url' not in leftval:
                continue
            if isinstance(node.right, ast.String):
                LOGGER.info('Found interesting url in JS: %s' % node.right.value[1:-1])
                self.check_link(url, node.right.value[2:-1])
            for item in node.right.__dict__.values():
                if isinstance(item, ast.String):
                    LOGGER.info('Found interesting url in JS: %s' % item.value[1:-1])
                    self.check_link(url, item.value[2:-1])

    def check_link(self, url, link_raw):
        '''checks a link to be relative or absolute and handle it according to
        settings'''
        link_raw = link_raw.strip()
        link_raw = link_raw.replace("'", "")
        link_raw = link_raw.replace("\\", "")
        host = self.extract_host(link_raw)
        if not host:
            # link is relative
            if self.base:
                new_link = urlparse.urljoin(self.base, link_raw)
            else:
                new_link = urlparse.urljoin(url, link_raw)
            # LOGGER.info('Putting link to resultQue: %s' % new_link)
            self.resultQue.put(new_link)
        else:
            # link is absoulte
            if 'www' not in host and 'www' in self.host:
                host = 'www.' + host
            if not self.release and host != self.host:
                return
            # LOGGER.info('Putting link to resultQue: %s' % link_raw)
            self.resultQue.put(link_raw)

    def find(self, key, dictionary):
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

    def run(self):
        '''
        main method of thread doing its work until inputQue is empty
        work is:
        -fetch content from urls given in inuputQue
        -extract links from a tags
        -scan html for mail adresses
        -optionally scan for keyword
        '''
        while not self.inputQue.empty():
            url = self.inputQue.get(False)
            parsed_url = urlparse.urlparse(url)
            try:
                # XXX: alter user-agent?
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows; U; Windows NT 6.1; '
                                  'rv:2.2) Gecko/20110201',
                }
                result = requests.get(
                    url,
                    allow_redirects=True,
                    timeout=REQUEST_TIMEOUT,
                    headers=headers
                )
                content = result.content
                self.bytes_done += len(content)
                text = result.text
            except Exception as e:
                LOGGER.warning(e)
                continue  # our requests has failed,but we don't care too much

            is_js = 'javascript' in result.headers.get('Content-Type')
            is_html = 'text/html' in result.headers.get('Content-Type')
            is_plain = 'plain' in result.headers.get('Content-Type')

            if is_plain:
                langnames = Guess().probable_languages(text)
                print('++++++++++++++++++++++++++++++++++++++++++++++++')
                print(langnames, url)
                print('++++++++++++++++++++++++++++++++++++++++++++++++')
                if 'Javascript' in langnames:
                    try:
                        json_from_plain = json.loads(text)
                    except:
                        json_from_plain = None
                        LOGGER.error('JSON evaluation failed on : %s' % text)
                    if json_from_plain:
                        LOGGER.info('Got JSON from plain: %s' % json_from_plain)

                if 'Python' in langnames:
                    try:
                        python_fom_plain = eval(text)
                    except:
                        LOGGER.error('Python evaluation failed on : %s' % text)
                        python_fom_plain = None
                    if python_fom_plain:
                        LOGGER.info('Got Python Code from plain: %s' % python_fom_plain)
                        if isinstance(python_fom_plain, dict):
                            urls = list(self.find('url', python_fom_plain))
                            LOGGER.info('Got urls from python dict: %s' % urls)
                            for link in urls:
                                self.check_link(url, link)

            if self.checkJS and is_js:
                self.scan_js(url, text)

            if not is_html:
                continue

            if self.keyword is not None:
                # TODO: needs a queue!
                for match in re.findall(self.keyword, text):
                    LOGGER.info('Found match on: %s' % url)

            for mail in re.findall(self.regex, text):
                if mail.split('.')[-1] in self.bad_endings:
                    continue
                # TODO: queue must also contain url mail was found on!
                self.mailQue.put(mail, False)

            for link_raw in self.extract_links(content):
                self.check_link(url, link_raw)

            self.base = None
            LOGGER.info('URL done: %s' % url)


class Crawler(object):

    def __init__(self, starturl, depth=5, numworkers=25, release=False,
                 keyword=None, javascript=False):

        self.starturl = starturl
        self.depth = depth
        self.numworkers = numworkers
        self.release = release
        self.javascript = javascript
        self.keyword = keyword

        self.inputQue = Queue()
        self.resultQue = Queue()
        self.mailQue = Queue()

        self.inputQue.put(starturl, False)

        self.linksdone = set()
        self.mail_adresses = set()

        self.bytes_done = 0

        self.host = urlparse.urlparse(starturl).netloc

        self.email_regex = re.compile(
            r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,6}\b", re.IGNORECASE
        )

        if self.keyword is not None:
            self.keyword_regex = re.compile(re.escape(keyword), re.IGNORECASE)
        else:
            self.keyword_regex = None

        LOGGER.info('-----> CRAWLER INITIALIZED <-----')

    def run(self, report=True):
        '''method to be called from executable'''
        starttime = time.time()
        try:
            self.crawl()
        except KeyboardInterrupt:  # ..abort crawler using CTRL+C
            pass
        except Exception:
            raise
        self.runtime = time.time() - starttime
        if report:
            self.report()

    def crawl(self):
        '''main loop'''
        for iteration in range(self.depth):

            threadlist = []

            for _ in range(self.numworkers):
                thread = Worker(
                    inputQue=self.inputQue,
                    resultQue=self.resultQue,
                    mailQue=self.mailQue,
                    host=self.host,
                    regex=self.email_regex,
                    keyword=self.keyword_regex,
                    release=self.release,
                    checkJS=self.javascript
                )
                thread.daemon = True
                thread.start()
                threadlist.append(thread)

            LOGGER.info('-----> THREADS STARTED <-----')

            for thread in threadlist:
                thread.join(THREAD_TIMEOUT)
                self.bytes_done += thread.bytes_done
            LOGGER.info('-----> GENERATION FINISHED <-----')

            results = []
            while not self.resultQue.empty():
                new_url = self.resultQue.get(False)
                # normalize url
                new_url_cleaned = urlparse.urlparse(new_url)
                new_url_cleaned = urlparse.urlunparse(new_url_cleaned)
                if new_url_cleaned not in self.linksdone:
                    self.linksdone.add(new_url_cleaned)
                    results.append(new_url_cleaned)

            # shuffle is useful in release mode to avoid making too many
            # requests to the same host at the same time
            random.shuffle(results)
            LOGGER.info('-----> LINKS SHUFFLED <-----')

            # refill inputQue
            for url in results:
                self.inputQue.put(url, False)

            while not self.mailQue.empty():
                new_mail = self.mailQue.get(False)
                self.mail_adresses.add(new_mail)

            # stop if no further links found
            if self.inputQue.empty():
                break

    def report(self):
        '''report result to logger (streaming to console by default). see
        logfacility for details'''
        print('-----> CRAWLER FINISHED <-----')
        print('-----> REPORT FOLLOWS <-----')
        print('-----> Got mails: <-----')
        for mail in self.mail_adresses:
            print(mail)
        print('-----> Mails found: <-----')
        print(len(self.mail_adresses))
        print('-----> Finished linklist: <-----')
        print(self.inputQue.empty())
        print('-----> Links done: <-----')
        print(len(self.linksdone))
        print('-----> Data processed [MB]: <-----')
        print(self.bytes_done * 1.0 / (10 ** 6))  # imperial bytes
        print('-----> Crawler runtime [s]: <-----')
        print(self.runtime)
