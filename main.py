import argparse
import crawler.crawler as crawler
import sys
import time

if __name__ == '__main__':
    if len(sys.argv) > 1:
        url = sys.argv[1]
        start = time.time()
        crawler.crawl(url.decode('utf-8'))
        runtime = time.time() - start
        print('Crawler took %s secdonds' % runtime)

    '''
    crawler.crawl('https://www.circle-marketing.de')
    print '###################################'
    crawler.crawl('https://www.perfact.de')
    print '###################################'
    crawler.crawl('http://www.bergmann82.de')
    '''
