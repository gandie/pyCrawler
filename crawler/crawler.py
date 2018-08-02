# -*- coding: utf-8 -*-
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
import Queue
import re
import urlparse
import random
from StringIO import StringIO
import time

# CUSTOM
import logfacility

# module settings
THREAD_TIMEOUT = 10
REQUEST_CON_TIMEOUT = 5
REQUEST_READ_TIMEOUT = 5
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

        self.bytes_done = 0

        self.parser = etree.HTMLParser()

        self.bad_endings = [
            'pdf', 'jpg', 'mp4', 'zip', 'tif', 'png', 'svg', 'jpg', 'exe', 'ico'
        ]
        self.bad_words = [
            'facebook', 'twitter', 'youtube', 'microsoft', 'google',
            'wikipedia', 'amazon', 'github', 'jquery'
        ]
        self.tag_map = {
            'a': 'href',
            'area': 'href',
            'base': 'href',
            'link': 'href',
            'frame': 'src',
            'iframe': 'src',
        }

        if self.checkJS:
            self.tag_map.update({
                'script': 'src',
            })
        
    def extract_host(self, url):
        return urlparse.urlparse(url).netloc

    def get_proto(self, url):
        return urlparse.urlparse(url).scheme
    
    def extract_links(self, html):
        '''
        build tree object from html and yield attributes from tags defined via
        tag_map
        '''
        # we need something that behaves like a filehandle here!
        stringio = StringIO(html)
        try:
            tree = etree.parse(stringio, self.parser)
        except Exception, e:
            LOGGER.warning(e)
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
                yield href

    def run(self):
        '''
        main method of thread doing its work until inputQue is empty
        work is:
        -extract links from a tags
        -scan html for mail adresses
        -optionally scan for keyword
        '''
        while not self.inputQue.empty():
            url = self.inputQue.get(False)
            parsed_url = urlparse.urlparse(url)
            try:
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
            except Exception as e:
                LOGGER.warning(e)
                continue  # our requests has failed,but we don't care too much

            if self.checkJS and 'javascript' in result.headers.get('Content-Type'):
                parser = Parser()
                tree = parser.parse(content)
                for node in nodevisitor.visit(tree):
                    '''
                    if isinstance(node, ast.String):
                        # if '/' in node.value and not node.value.startswith('<'):
                        LOGGER.info('Found string in JS: %s' % node.value)
                    '''
                    if not isinstance(node, ast.Assign):
                        continue
                    leftval = getattr(node.left, 'value', '')
                    if not leftval:
                        continue
                    if 'url' not in leftval:
                        continue
                    if isinstance(node.right, ast.String):
                        LOGGER.info('Found interesting url in JS: %s' % node.right.value)
                    for item in node.right.__dict__.values():
                        if isinstance(item, ast.String):
                            LOGGER.info('Found interesting url in JS: %s' % item.value)
                
            if 'text/html' not in result.headers.get('Content-Type'):
                continue

            if self.keyword is not None:
                for match in re.findall(self.keyword, content):
                    LOGGER.info('Found match on: %s' % url)

            for mail in re.findall(self.regex, content):
                if mail.split('.')[-1] in self.bad_endings:
                    continue
                self.mailQue.put(mail, False)
            for link_raw in self.extract_links(content):
                link_raw = link_raw.strip()
                # print(link_raw)
                host = self.extract_host(link_raw)
                # print(host)
                if not host:
                    # link is relative or something else
                    # TODO: this part is broken for some relative links!
                    #myhost = self.extract_host(url)
                    #myproto = self.get_proto(url)
                    new_link = urlparse.urljoin(url, link_raw)
                    '''
                    if link_raw.startswith('/'):
                        new_link = '{proto}://{myhost}{link_raw}'.format(
                            proto=parsed_url.scheme,
                            myhost=parsed_url.netloc,
                            link_raw=link_raw
                        )
                    else:
                        # print url
                        cut_url = url.rsplit('/', 1)[0]
                        if parsed_url.netloc in cut_url:
                            new_link = cut_url + '/' + link_raw
                            # new_link = urlparse.urljoin(cut_url, link_raw)
                        else:
                            new_link = url + '/' + link_raw
                            # new_link = urlparse.urljoin(url, link_raw)
                    '''
                    # print(new_link)
                    # if new_link.startswith('http'):
                    self.resultQue.put(new_link)
                else:
                    # link is absoulte
                    if 'www' not in host and 'www' in self.host:
                        host = 'www.' + host
                    if not self.release and host != self.host:
                        continue
                    self.resultQue.put(link_raw)
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

        self.inputQue = Queue.Queue()
        self.resultQue = Queue.Queue()
        self.mailQue = Queue.Queue()

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
        except KeyboardInterrupt:
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
        LOGGER.info('-----> CRAWLER FINISHED <-----')
        LOGGER.info('-----> REPORT FOLLOWS <-----')
        LOGGER.info('From starturl %s found following sites:' % self.starturl)
        for link in self.linksdone:
            LOGGER.info(link)
        LOGGER.info('-----> Got mails: <-----')
        for mail in self.mail_adresses:
            LOGGER.info(mail)
        LOGGER.info('-----> Mails found: <-----')
        LOGGER.info(len(self.mail_adresses))
        LOGGER.info('-----> Finished linklist: <-----')
        LOGGER.info(self.inputQue.empty())
        LOGGER.info('-----> Links done: <-----')
        LOGGER.info(len(self.linksdone))
        LOGGER.info('-----> Data processed [MB]: <-----')
        LOGGER.info(self.bytes_done * 1.0 / (10 ** 6))  # imperial bytes
        LOGGER.info('-----> Crawler runtime [s]: <-----')
        LOGGER.info(self.runtime)
