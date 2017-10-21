# pyCrawler
A simple Python page crawler to extract mail addresses.

Written as pythonic solution of a programming excercise,
intended for training purposes.

# Installation

This python package can be installed (optionally into a <a href="http://docs.python-guide.org/en/latest/dev/virtualenvs/#lower-level-virtualenv">virtualenv</a>)
after requirements have been installed:

```bash
pip install -r requirements.txt
python setup.py install
```

It is also possible to build a debian-package using the <a href="https://github.com/nylas/make-deb">make-deb</a>
toolchain.

# Usage

```
usage: pyCrawler [-h] [-d DEPTH] [-n NUMWORKERS] [-r] [-k KEYWORD] url

positional arguments:
  url                   This is the url to start crawling from

optional arguments:
  -h, --help            show this help message and exit
  -d DEPTH, --depth DEPTH
                        How many generation of links to follow. Default 10
  -n NUMWORKERS, --numworkers NUMWORKERS
                        Number of crawlers spawned. Default 25
  -r, --release         Allow the crawler to leave host given by url
  -k KEYWORD, --keyword KEYWORD
                        Give optional keyword to search for
```
