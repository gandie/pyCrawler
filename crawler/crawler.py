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

# PIP
import requests

# html / xml parser
from lxml import etree

# BUILTIN
import threading
from queue import Queue
import re
import urllib.parse as urlparse

import random
from io import BytesIO
import time
import urllib3

# CUSTOM
import crawler.logfacility as logfacility
import crawler.links as links

# module settings
THREAD_TIMEOUT = 10
REQUEST_CON_TIMEOUT = 2
REQUEST_READ_TIMEOUT = 5
REQUEST_TIMEOUT = (REQUEST_CON_TIMEOUT, REQUEST_READ_TIMEOUT)

LOGGER = logfacility.build_logger()
urllib3.disable_warnings()


class Worker(threading.Thread):
    '''
    Worker thread started by Crawler.crawl() method
    Fetches urls from inputQue and puts mail addresses found to mailQue and new
    links to resultQue.

    Also has some scanning abilities.
    '''
    def __init__(self, inputQue, resultQue, mailQue, hostQue, host, regex, keyword,
                 release, checkJS=False, checkPlain=False, map_hosts=False,
                 **kwargs):

        super(Worker, self).__init__(**kwargs)

        self.inputQue = inputQue
        self.resultQue = resultQue
        self.mailQue = mailQue
        self.hostQue = hostQue

        self.host = host
        self.release = release
        self.checkJS = checkJS
        self.checkPlain = checkPlain
        self.keyword = keyword
        self.regex = regex
        self.map_hosts = map_hosts

        self.base = None

        self.bytes_done = 0

        self.bad_endings = [
            'pdf', 'jpg', 'mp4', 'zip', 'tif', 'png', 'svg', 'jpg', 'exe',
            'ico', 'css', 'mpg',  # we're not interested in css, for now...
        ]

        self.bad_words = [
            'facebook', 'twitter', 'youtube', 'microsoft', 'google',
            'wikipedia', 'amazon', 'github', 'jquery', 'bootstrap',
            'instagram', 'vimeo', 'reddit', 'pinterest', 'linkedin',
            'mozilla', 'wordpress', 'creativecommons', 'wikiquote',
            'soundcloud', 'bandcamp', 'apple',
        ]

        self.tag_map = {
            'a': 'href',
            'area': 'href',
            'base': 'href',
            'link': 'href',
            'frame': 'src',
            'iframe': 'src',
            'base': 'href,',  # important to avoid loops on relative links
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

        parser = etree.HTMLParser()

        # we need something that behaves like a filehandle here!
        filehandle = BytesIO(html)

        try:
            tree = etree.parse(filehandle, parser)
        except Exception as e:
            LOGGER.warning(e)
            filehandle.close()
            return  # abort if we got invalid stuff

        filehandle.close()
        for element in tree.iter():
            if element.tag not in self.tag_map:
                continue
            href = element.get(self.tag_map[element.tag])

            if not href:
                continue

            if href.split('.')[-1] in self.bad_endings:
                continue

            for bad_word in self.bad_words:
                if bad_word in href:
                    break
            else:  # read else like "nobreak"
                # XXX: check following stmnt
                if element.tag == 'base':
                    self.base = href
                yield href

    def check_link(self, url, link_raw):
        '''checks a link to be relative or absolute and handle it according to
        settings'''
        link_raw = link_raw.strip()
        link_raw = link_raw.replace("'", "")
        link_raw = link_raw.replace("\\", "")

        if 'mailto:' in link_raw:
            return

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

            another_host = host != self.host

            if another_host and self.map_hosts:
                self.hostQue.put((self.base if self.base else self.host, host))

            # skip links to other hosts
            if not self.release and another_host:
                return

            # LOGGER.info('Putting link to resultQue: %s' % link_raw)
            self.resultQue.put(link_raw)

    def request_url(self, url):
        '''use requests to call given url. returns raw bytes content, text and
        content-type'''
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
                headers=headers,
                verify=False
            )
            content = result.content
            text = result.text
            content_type = result.headers.get('Content-Type')
            self.bytes_done += len(content)
        except Exception as e:
            # our requests has failed,but we don't care too much
            LOGGER.warning(e)
            return None

        return content, text, content_type

    def scan_mails(self, url, text):
        '''use regex to check given text for mails, put mails found to Queue'''
        for mail in re.findall(self.regex, text):
            if mail.split('.')[-1] in self.bad_endings:
                continue
            # TODO: queue must also contain url mail was found on!
            self.mailQue.put(mail, False)

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

            target_host = self.extract_host(url)
            if self.release and target_host != self.host:
                LOGGER.info(
                    'Host changed from %s to %s' % (self.host, target_host)
                )
                self.host = target_host

            request_result = self.request_url(url)

            if not request_result:
                continue
            content, text, content_type = request_result

            if not content_type:
                LOGGER.info('Unknown content-type found on: %s' % url)
                continue

            LOGGER.info(
                'Got content-type %s from url %s' % (content_type, url)
            )

            is_js = 'javascript' in content_type
            is_html = 'text/html' in content_type
            is_plain = 'plain' in content_type

            if is_plain and self.checkPlain:
                import crawler.guess as scan_module
                scan_module.scan_plain(self, url, text)

            if is_js and self.checkJS:
                import crawler.guess as scan_module
                scan_module.scan_js(self, url, text)

            if not is_html:
                continue

            if self.keyword is not None:
                # TODO: needs a queue!
                for match in re.findall(self.keyword, text):
                    LOGGER.info('Found match on: %s' % url)

            self.scan_mails(url, text)

            new_links = links.extract_links(text, url, self.release)
            for link_d in new_links:
                if not link_d:
                    continue
                if (self.release and link_d['new_host']) or \
                   (not self.release and link_d['new_host'] is None):
                    self.resultQue.put(link_d['url'])
                if link_d['new_host'] and self.map_hosts:
                    self.hostQue.put((self.host, link_d['new_host']))
            LOGGER.info('URL done: %s' % url)


class Crawler(object):
    '''main object of crawler module called from executable. handles worker
    threads and reports results after main loop is finished'''

    def __init__(self, starturl, depth=5, numworkers=25, release=False,
                 keyword=None, javascript=False, plain=False, map_hosts=False,
                 loglevel=30):

        LOGGER.setLevel(loglevel)

        self.starturl = starturl
        self.depth = depth
        self.numworkers = numworkers
        self.release = release
        self.javascript = javascript
        self.plain = plain
        self.map_hosts = map_hosts

        self.keyword = keyword

        self.inputQue = Queue()
        self.resultQue = Queue()
        self.mailQue = Queue()
        self.hostQue = Queue()

        self.inputQue.put(starturl, False)

        self.linksdone = set()
        self.mail_adresses = set()
        self.host_map = set()

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
                    hostQue=self.hostQue,
                    host=self.host,
                    regex=self.email_regex,
                    keyword=self.keyword_regex,
                    release=self.release,
                    checkJS=self.javascript,
                    checkPlain=self.plain,
                    map_hosts=self.map_hosts
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

            while not self.hostQue.empty():
                host_tuple = self.hostQue.get(False)
                self.host_map.add(host_tuple)

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
        '''
        report result tp console
        '''
        print('-----> CRAWLER FINISHED <-----')
        print('-----> REPORT FOLLOWS <-----')
        print('-----> Links done: <-----')
        for link in self.linksdone:
            print(link)
        print('-----> Got mails: <-----')
        for mail in self.mail_adresses:
            print(mail)
        print('-----> Mails found: <-----')
        print(len(self.mail_adresses))
        print('-----> Finished linklist: <-----')
        print(self.inputQue.empty())
        print('-----> Links done: <-----')
        print(len(self.linksdone))
        if self.map_hosts:
            import crawler.draw as draw_module
            for from_host, to_host in self.host_map:
                print('%s --> %s' % (from_host, to_host))
            draw_module.draw_graph(self.host_map)
        print('-----> Data processed [MB]: <-----')
        print(self.bytes_done * 1.0 / (10 ** 6))  # imperial bytes
        print('-----> Crawler runtime [s]: <-----')
        print(self.runtime)
