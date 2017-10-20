import argparse
import crawler.crawler as crawler
import sys
import time

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('url', help='This is the url to start crawling from')
    parser.add_argument(
        '-d',
        '--depth',
        help='How many generation of links to follow. Default 10',
        type=int,
        default=10
    )
    parser.add_argument(
        '-n',
        '--numworkers',
        help='Number of crawlers spawned. Default 25',
        type=int,
        default=25
    )
    parser.add_argument(
        '-r',
        '--release',
        help='Allow the crawler to leave host given by url',
        action='store_true',
        default=False
    )

    args = parser.parse_args()

    url = args.url
    start = time.time()
    crawler.crawl(
        starturl=url.decode('utf-8'),
        depth=args.depth,
        numworkers=args.numworkers,
        release=args.release
    )
    runtime = time.time() - start
    print('Crawler took %s secdonds' % runtime)
