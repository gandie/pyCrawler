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

# builtin
import threading
import Queue
import re
import urlparse
from StringIO import StringIO

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
    Worker thread started by crawl() function
    See run method for detaills
    '''
    def __init__(self, inputQue, resultQue, mailQue, host, regex, keyword,
                 release, **kwargs):
        super(Worker, self).__init__(**kwargs)
        self.inputQue = inputQue
        self.resultQue = resultQue
        self.mailQue = mailQue
        self.host = host
        self.release = release
        self.keyword = keyword
        self.regex = regex
        self.parser = etree.HTMLParser()

        self.bad_endings = [
            'pdf', 'jpg', 'mp4', 'zip', 'tif', 'png', 'svg', 'jpg', 'exe'
        ]
        self.bad_words = [
            'facebook', 'twitter', 'youtube', 'microsoft', 'google',
            'wikipedia', 'amazon'
        ]
        self.tag_map = {
            'a': 'href',
            'frame': 'src',
        }

    def extract_host(self, url):
        return urlparse.urlparse(url).netloc

    def extract_links(self, html):
        '''
        build tree object from html and yield href atrributes of 'a' tags
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
            except Exception, e:
                LOGGER.warning(e)
                continue  # our requests has failed,but we don't care too much

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
                host = self.extract_host(link_raw)
                if not host:
                    # link is relative or something else
                    new_link = urlparse.urljoin(url, link_raw)
                    if new_link.startswith('http'):
                        self.resultQue.put(new_link)
                else:
                    # link is absoulte
                    if 'www' not in host:
                        host = 'www.' + host
                    if not self.release and host != self.host:
                        continue
                    self.resultQue.put(link_raw)
            LOGGER.info('URL done: %s' % url)


def crawl(starturl, depth=5, numworkers=25, release=False, keyword=None):
    '''
    main function of crawler module
    starts ques, prepares arguments and runs main loop:
    -build and start threads
    -catch threads when they have finished (or time out)
    -collect results from ques
    '''
    inputQue = Queue.Queue()
    resultQue = Queue.Queue()
    mailQue = Queue.Queue()

    inputQue.put(starturl, False)

    linksdone = set()
    mail_adresses = set()

    host = urlparse.urlparse(starturl).netloc

    reobj = re.compile(
        r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,6}\b", re.IGNORECASE
    )
    if keyword is not None:
        keyword_reobj = re.compile(re.escape(keyword), re.IGNORECASE)
    else:
        keyword_reobj = None

    # main loop
    for iteration in xrange(depth):

        threadlist = []

        for _ in xrange(numworkers):
            thread = Worker(
                inputQue=inputQue,
                resultQue=resultQue,
                mailQue=mailQue,
                host=host,
                regex=reobj,
                keyword=keyword_reobj,
                release=release
            )
            thread.daemon = True
            thread.start()
            threadlist.append(thread)

        for thread in threadlist:
            thread.join(THREAD_TIMEOUT)

        LOGGER.info('-----> GENERATION FINISHED <-----')

        while not resultQue.empty():
            new_url = resultQue.get(False)
            if new_url not in linksdone:
                linksdone.add(new_url)
                inputQue.put(new_url, False)

        while not mailQue.empty():
            new_mail = mailQue.get(False)
            mail_adresses.add(new_mail)

        # stop if no further links found
        if inputQue.empty():
            break

    LOGGER.info('-----> CRAWLER FINISHED <-----')
    LOGGER.info('-----> REPORT FOLLOWS <-----')
    LOGGER.info('From starturl %s found following sites:' % starturl)
    for link in linksdone:
        LOGGER.info(link)
    LOGGER.info('-----> Got mails: <-----')
    for mail in mail_adresses:
        LOGGER.info(mail)
    LOGGER.info('-----> Finished linklist: <-----')
    LOGGER.info(inputQue.empty())
    LOGGER.info('-----> Links done: <-----')
    LOGGER.info(len(linksdone))
