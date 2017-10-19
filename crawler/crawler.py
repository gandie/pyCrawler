import requests
import threading
import Queue
#from BeautifulSoup import BeautifulSoup
import re
import urlparse
from lxml import etree
from StringIO import StringIO


class Worker(threading.Thread):

    def __init__(self, inputQue, resultQue, mailQue, host, regex, **kwargs):
        super(Worker, self).__init__(**kwargs)
        self.inputQue = inputQue
        self.resultQue = resultQue
        self.mailQue = mailQue
        self.host = host
        #self.starturl_stripped = self.starturl.replace('www.', '')
        self.regex = regex
        self.parser = etree.HTMLParser()

        self.bad_endings = [
            'pdf', 'jpg', 'mp4'
        ]

    def extract_host(self, url):
        return urlparse.urlparse(url).netloc

    def extract_links(self, html):
        '''
        build tree object from html and yield href atrributes of a tags
        '''
        # we need something that behaves like a file here!
        stringio = StringIO(html)
        tree = etree.parse(stringio, self.parser)
        for element in tree.iter():
            if element.tag != 'a':
                continue
            href = element.get('href')
            if not href:
                continue
            if href.split('.')[-1] not in self.bad_endings:
                yield href

    def run(self):
        '''
        main method of thread doing its work until inputQue is empty
        work is:
        -extract links from a tags
        -scan html for mail adresses
        hopefully returns peacefully afterwards
        '''
        while not self.inputQue.empty():
            url = self.inputQue.get(False)
            print 'My url is: %s' % url
            try:
                result = requests.get(
                    url,
                    allow_redirects=True,
                    timeout=5.0
                )
                content = result.content
                #soup = BeautifulSoup(content)
            except Exception, e:
                print str(e)
                continue

            # print result.headers.get('Content-Type'), url
            if 'text/html' not in result.headers.get('Content-Type'):
                continue

            for mail in re.findall(self.regex, content):
                self.mailQue.put(mail, False)
            for link_raw in self.extract_links(content):
                host = self.extract_host(link_raw)
                if not host:
                    # link is relative or something
                    new_link = urlparse.urljoin(url, link_raw)
                    #print new_link
                    if new_link.startswith('http'):
                        self.resultQue.put(new_link)
                else:
                    # link is absoulte
                    if 'www' not in host:
                        host = 'www.' + host
                    if host != self.host:
                        continue
                    self.resultQue.put(link_raw)


def crawl(starturl):

    inputQue = Queue.Queue()
    resultQue = Queue.Queue()
    mailQue = Queue.Queue()

    inputQue.put(starturl, False)

    depth = 5
    numworkers = 25
    linksdone = []
    mail_adresses = []

    host = urlparse.urlparse(starturl).netloc

    reobj = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,6}\b", re.IGNORECASE)
    # reobj = re.compile(ur'[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+', re.MULTILINE | re.IGNORECASE)
    for iteration in xrange(depth):

        threadlist = []

        for _ in xrange(numworkers):
            thread = Worker(
                inputQue=inputQue,
                resultQue=resultQue,
                mailQue=mailQue,
                host=host,
                regex=reobj
            )
            thread.daemon = True
            thread.start()
            threadlist.append(thread)

        for thread in threadlist:
            thread.join(10)

        print '------------------------------'
        print 'GENERATION FINISHED'
        print '------------------------------'

        while not resultQue.empty():
            new_url = resultQue.get(False)
            if new_url not in linksdone:
                inputQue.put(new_url, False)
                linksdone.append(new_url)

        while not mailQue.empty():
            new_mail = mailQue.get(False)
            if new_mail not in mail_adresses:
                mail_adresses.append(new_mail)

    print '########################'
    print 'From starturl %s found following sites:' % starturl
    for link in linksdone:
        print link
    print '########################'
    print 'Got mails:'
    for mail in mail_adresses:
        print mail
