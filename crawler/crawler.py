import requests
import threading
import Queue
from BeautifulSoup import BeautifulSoup
import re


class Worker(threading.Thread):

    def __init__(self, inputQue, resultQue, starturl, regex, **kwargs):
        super(Worker, self).__init__(**kwargs)
        self.inputQue = inputQue
        self.resultQue = resultQue
        self.starturl = starturl
        self.starturl_stripped = self.starturl.replace('www.', '')
        self.regex = regex

    def run(self):
        while not self.inputQue.empty():
            url = self.inputQue.get(False)
            # print 'My url is: %s' % url
            try:
                result = requests.get(url, allow_redirects=True)
                content = result.content
                soup = BeautifulSoup(content)
            except Exception, e:
                print str(e)
                continue
            print re.findall(self.regex, content)

            # content = content.decode('utf-8')
            for link in soup.findAll('a'):
                link_raw = link.get('href')
                # print link_raw
                if link_raw is None:
                    continue
                if self.starturl in link_raw or self.starturl_stripped in link_raw:
                    # print 'new url found: %s' % link_raw
                    self.resultQue.put(link_raw)
                    continue
                if link_raw.startswith('/'):
                    new_link = self.starturl + link_raw
                    # print 'relative link found: %s' % new_link
                    self.resultQue.put(new_link)
                    continue

                if link_raw.startswith('./'):
                    new_link = self.starturl + link_raw[1:]
                    # print 'relative link found: %s' % new_link
                    self.resultQue.put(new_link)
                    continue

                if u'/' not in link_raw:
                    new_link = self.starturl + u'/' + link_raw
                    # print 'relative link found: %s' % new_link
                    self.resultQue.put(new_link)
                    continue

                print link_raw, self.starturl_stripped
                #new_link = self.starturl + u'/' + link_raw
                #self.resultQue.put(new_link)


def crawl(starturl):

    inputQue = Queue.Queue()
    resultQue = Queue.Queue()

    inputQue.put(starturl, False)

    depth = 10
    numworkers = 25
    linksdone = []

    reobj = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,6}\b", re.IGNORECASE)
    # reobj = re.compile(ur'[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+', re.MULTILINE | re.IGNORECASE)
    for iteration in xrange(depth):

        threadlist = []

        for _ in xrange(numworkers):
            thread = Worker(inputQue, resultQue, starturl, reobj)
            thread.start()
            threadlist.append(thread)

        for thread in threadlist:
            thread.join()

        while not resultQue.empty():
            new_url = resultQue.get(False)
            if new_url not in linksdone:
                inputQue.put(new_url, False)
                linksdone.append(new_url)

    print '########################'
    print 'From starturl %s found following sites:' % starturl
    for link in linksdone:
        print link
