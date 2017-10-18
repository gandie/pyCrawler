import argparse
import crawler.crawler as crawler
import sys

if __name__ == '__main__':
    if len(sys.argv) > 1:
        url = sys.argv[1]
        crawler.crawl(url.decode('utf-8'))

    '''
    crawler.crawl('https://www.circle-marketing.de')
    print '###################################'
    crawler.crawl('https://www.perfact.de')
    print '###################################'
    crawler.crawl('http://www.bergmann82.de')
    '''
