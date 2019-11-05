# -*- coding: utf-8 -*-
#
# links.py - helper module of pyCrawler to extract links from html
#
# Copyright (c) 2019 Lars Bergmann
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

from lxml import etree
from io import StringIO
import urllib.parse as urlparse


bad_endings = [
    'pdf', 'jpg', 'mp4', 'zip', 'tif', 'png', 'svg', 'jpg', 'exe',
    'ico', 'css', 'mpg',  # we're not interested in css, for now...
]

bad_words = [
    'facebook', 'twitter', 'youtube', 'microsoft', 'google',
    'wikipedia', 'amazon', 'github', 'jquery', 'bootstrap',
    'instagram', 'vimeo', 'reddit', 'pinterest', 'linkedin',
    'mozilla', 'wordpress', 'creativecommons', 'wikiquote',
    'soundcloud', 'bandcamp', 'apple',
]

tag_map = {
    'a': 'href',
    'area': 'href',
    'base': 'href',
    'link': 'href',
    'frame': 'src',
    'iframe': 'src',
    'base': 'href,',  # important to avoid loops on relative links
}


def extract_links(html, source_url, release):
    '''
    if not isinstance(html, bytes):
        html = bytes(html, 'utf-8')
    '''
    results = []
    links = list(parse_html(html))
    bases = [item[1] for item in links]
    has_base = any(base for base in bases)
    if has_base:
        base = [base for base in bases if base][0]
    else:
        base = None
    for link, base in links:
        results.append(check_link(
            source_url=source_url,
            link_raw=link,
            release=release,
            base=base
        ))
    return results


def extract_host(url):
    return urlparse.urlparse(url).netloc


def parse_html(html):
    '''
    build tree object from html and yield attributes from tags defined via
    tag_map. also filters bad_words and bad_endings
    '''

    base = None

    parser = etree.HTMLParser()

    # we need something that behaves like a filehandle here!
    filehandle = StringIO(html)

    try:
        tree = etree.parse(filehandle, parser)
    except Exception as e:
        LOGGER.warning(e)
        filehandle.close()
        return  # abort if we got invalid stuff

    filehandle.close()
    for element in tree.iter():
        if element.tag not in tag_map:
            continue
        href = element.get(tag_map[element.tag])

        if not href:
            continue

        if href.split('.')[-1] in bad_endings:
            continue

        for bad_word in bad_words:
            if bad_word in href:
                break
        else:  # read else like "nobreak"
            # XXX: check following stmnt
            if element.tag == 'base':
                base = href
            yield href, base


def check_link(source_url, link_raw, release, base):
    '''checks a link to be relative or absolute and handle it according to
    settings'''

    source_host = extract_host(source_url)

    link_raw = link_raw.strip()
    link_raw = link_raw.replace("'", "")
    link_raw = link_raw.replace("\\", "")

    if 'mailto:' in link_raw or 'tel:' in link_raw:
        return

    host = extract_host(link_raw)

    if not host:
        # link is relative
        if base:
            new_link = urlparse.urljoin(base, link_raw)
        else:
            new_link = urlparse.urljoin(source_url, link_raw)
        # LOGGER.info('Putting link to resultQue: %s' % new_link)
        return {
            'url': new_link,
            'new_host': None,
        }
    else:
        # link is absoulte
        if 'www' not in host and 'www' in source_host:
            host = 'www.' + host

        another_host = host != source_host

        if another_host:
            new_host = host
        else:
            new_host = None

        # skip links to other hosts
        if not release and another_host:
            return

        return {
            'url': link_raw,
            'new_host': new_host,
        }
    return results
