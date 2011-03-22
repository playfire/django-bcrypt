#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='django-bcrypt',
    description="bcrypt password hash support for Django.",
    version='0.1',
    url='http://code.playfire.com/django-bcrypt',

    author='Playfire.com',
    author_email='tech@playfire.com',
    license='BSD',

    packages=find_packages(),
)
