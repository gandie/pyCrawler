# Copyright (c) 2019 Lars Bergmann
#
# async_crawler.py - experimental crawler module using requests_html library
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

import requests_html
import requests
import urllib.parse as urlparse
import time
import urllib3

REQUEST_CON_TIMEOUT = 2
REQUEST_READ_TIMEOUT = 5
REQUEST_TIMEOUT = (REQUEST_CON_TIMEOUT, REQUEST_READ_TIMEOUT)

urllib3.disable_warnings()


class AsyncCrawler(object):

    def __init__(self, starturl, depth=10, release=False):
        self.session = requests_html.AsyncHTMLSession()
        self.urls = [starturl]
        self.depth = depth
        self.urls_done = []
        self.host = urlparse.urlparse(starturl).netloc
        self.release = release

    def run(self):
        for iteration in range(self.depth):
            if not self.urls:
                break
            num_requests = len(self.urls)
            results = self.session.run(*[self.get_url for _ in range(num_requests)])
            for item in results:
                try:
                    new_links = item.html.absolute_links
                except:
                    continue
                for link in new_links:
                    new_host = urlparse.urlparse(link).netloc
                    if 'www' not in new_host and 'www' in self.host:
                        new_host = 'www.' + new_host
                    if new_host != self.host and self.host not in new_host and not self.release:
                        continue
                    if link not in self.urls_done:
                        self.urls.append(link)

    async def get_url(self):
        try:
            url = self.urls.pop()
        except KeyError:  # list is empty, abort
            return
        try:
            r = await self.session.get(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                verify=False
            )
        except:
            return
        self.urls_done.append(url)
        return r


if __name__ == '__main__':
    import sys
    starturl = sys.argv[1]
    print(starturl)
    starttime = time.time()
    c = AsyncCrawler(starturl=starturl, release=False)
    c.run()
    print(c.urls_done)
    print(len(c.urls_done))
    print('Done. Took %s seconds' % (time.time() - starttime))
