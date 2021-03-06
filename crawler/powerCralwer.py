import requests
from lxml import etree
from queue import Queue as TQueue
from multiprocessing import Process
from multiprocessing import JoinableQueue as MQueue
import urllib.parse as urlparse
from io import BytesIO
import threading
import time
import re
import multiprocessing
import os

url_queue = MQueue()
html_queue = MQueue()


class HTMLProcessor(Process):

    def __init__(self, inputQue, outputQue, host, release, proc_id, **kwargs):
        super(HTMLProcessor, self).__init__()
        self.inputQue = inputQue
        self.outputQue = outputQue
        self.host = host
        self.release = release
        self.kwargs = kwargs
        self.parser = etree.HTMLParser()
        self.base = None
        self.proc_id = 'Process%s' % proc_id

        self.filename = 'proc%s_log.txt' % proc_id
        self.filehandle = open(self.filename, 'a')
        self.mailsfound = set()

        self.bad_endings = [
            'pdf', 'jpg', 'mp4', 'zip', 'tif', 'png', 'svg', 'jpg', 'exe',
            'ico', 'css', 'mpg'  # we're not interested in css, for now...
        ]
        self.bad_words = [
            'facebook', 'twitter', 'youtube', 'microsoft', 'google',
            'wikipedia', 'amazon', 'github', 'jquery', 'bootstrap',
            'instagram', 'vimeo'
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

        self.email_regex = re.compile(
            r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,6}\b", re.IGNORECASE
        )

    def scan_mails(self, url, text):
        '''use regex to check given text for mails, put mails found to Queue'''
        for mail in re.findall(self.email_regex, text):
            if mail.split('.')[-1] in self.bad_endings:
                continue
            if mail not in self.mailsfound:
                self.mailsfound.add(mail)
                self.filehandle.write(mail + '\n')

    def extract_host(self, url):
        if self.host in url:
            return self.host
        return urlparse.urlparse(url).netloc

    def extract_links(self, html):
        ''' CPUTASK
        build tree object from html and yield attributes from tags defined via
        tag_map. also filters bad_words and bad_endings
        '''
        # we need something that behaves like a filehandle here!
        filehandle = BytesIO(html)
        try:
            tree = etree.parse(filehandle, self.parser)
        except Exception as e:
            LOGGER.warning(e)
            return  # abort if we got invalid stuff
        finally:
            filehandle.close()
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
            if self.base:
                new_link = urlparse.urljoin(self.base, link_raw)
            else:
                new_link = urlparse.urljoin(url, link_raw)
            # print('got new link %s' % new_link)
            url_queue.put(new_link)
        else:
            # link is absoulte
            if 'www' not in host and 'www' in self.host:
                host = 'www.' + host
            if not self.release and host != self.host:
                return
            url_queue.put(link_raw)

    def run(self):
        """Build some CPU-intensive tasks to run via multiprocessing here."""
        while True:
            try:
                result_d = self.inputQue.get(timeout=60)
            except:
                self.filehandle.close()
                break
            url = result_d['url']
            # print('Working on %s' % url)
            content = result_d['content']
            text = result_d['text']
            self.scan_mails(url, text)
            for link in self.extract_links(content):
                self.check_link(url, link)
            #print('Work done on %s' % url)
            self.inputQue.task_done()
        print('empty, aborting processor%s' % self.proc_id)
        return True


def fetch_url(url):
    print('Trying url: %s' % url)
    try:
        # XXX: alter user-agent?
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows; U; Windows NT 6.1; '
                          'rv:2.2) Gecko/20110201',
        }
        result = requests.get(
            url,
            allow_redirects=True,
            timeout=(1, 1),
            headers=headers
        )
        content = result.content
        text = result.text
        content_type = result.headers.get('Content-Type')
    except Exception as e:
        # our requests has failed,but we don't care too much
        # LOGGER.warning(e)
        # print(e)
        return None

    return content, text, content_type


def process_urls():
    while True:
        try:
            cur_url = url_queue.get(timeout=60)
        except:
            print('empty requester, aborting...')
            break
        if cur_url not in linksdone:
            linksdone.append(cur_url)
            # print('links done: %s' % linksdone)
        else:
            url_queue.task_done()
            continue
        #print('now url %s' % cur_url)
        result = fetch_url(cur_url)
        # print('result from url %s' % cur_url)
        if result:
            content, text, content_type = result
            if content_type and 'text/html' in content_type:
                process_d = {
                    'url': cur_url,
                    'content': content,
                    'text': text
                }
                html_queue.put(process_d)
                # print('result put to html queue %s' % cur_url)
        #print('url done %s' % cur_url)
        url_queue.task_done()
    return True


if __name__ == '__main__':
    linksdone = []

    start_address = 'https://www.perfact.de/'
    myhost = urlparse.urlparse(start_address).netloc

    url_queue.put(start_address)

    num_requester = 1000
    num_processors = multiprocessing.cpu_count()

    for i in range(num_requester):
        my_thread = threading.Thread(target=process_urls)
        # my_thread.daemon = True
        my_thread.start()

    procs = []
    for i in range(num_processors):
        my_processor = HTMLProcessor(
            inputQue=html_queue,
            outputQue=url_queue,
            host=myhost,
            release=True,
            proc_id=i
        )
        # my_processor.daemon = True
        my_processor.start()
        procs.append(my_processor)

    url_queue.join()
    html_queue.join()

    try:
        while True:
            procs = [p for p in procs if p.is_alive()]
            print('Working. Living procs:%s' % len(procs))
            time.sleep(.5)
            if not len(procs):
                break
    except KeyboardInterrupt:
        print('KeyboardInterrupt')

    print('now i am done...reducing mails to one file...')
    os.system('cat proc* | sort --unique > mails.txt')
    os.system('rm proc*')
