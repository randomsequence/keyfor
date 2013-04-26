import os
from setuptools import setup, find_packages
from keyfor import VERSION

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
        f = open(os.path.join(os.path.dirname(__file__), fname))
        long_desc = f.read()
        f.close()
        return long_desc

setup(
    name = 'keyfor',
    version = VERSION,
    description = 'keyfor keeps usernames & passwords',
    long_description=read('README.md'),
    author = 'Johnnie Walker',
    author_email = 'mrwalker@randomsequence.com',
    url = 'https://github.com/randomsequence/keyfor',
    packages=find_packages(),
    requires=['keyring', 'pycrypto', 'docopt'],
    entry_points={
            'console_scripts':[
                'keyfor=keyfor.__main__:main'
                ]
        },
    install_requires=['setuptools'],
    classifiers=[
            'Development Status :: 3 - Alpha',
            'Environment :: Console',
            'Intended Audience :: End Users/Desktop',
            'License :: OSI Approved :: GNU General Public License (GPL)',
            'Operating System :: OS Independent',
            'Programming Language :: Python',
            'Topic :: Utilities'
        ]
)