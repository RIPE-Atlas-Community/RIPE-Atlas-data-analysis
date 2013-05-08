#!/usr/bin/env python

from setuptools import setup, find_packages

from ripeatlas.analysis import __version__


setup(name='ripeatlas-data-analysis',
      version=__version__,
      description="Tools and class libraries for RIPEAtlas data analysis",
      author_email='atlas-bugs@ripe.net',
      url='',
      install_requires=['argparse','dnspython','simplejson'],
      packages=find_packages(),
      scripts=["scripts/atlasreport.py", "scripts/dnsReport.sh", "scripts/dnsReport.pl", "scripts/decode_abuf.py"]
     )
