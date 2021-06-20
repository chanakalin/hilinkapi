#!/usr/bin/python3

from distutils.core import setup
from distutils.extension import Extension
from Cython.Build import cythonize
from Cython.Distutils import build_ext
import glob, os

ext_modules = cythonize([
Extension("HiLinkAPI",  ["HiLinkAPI.py"]),
],
compiler_directives=dict(always_allow_keywords=True, language_level='3')
)

setup(
    name = 'hilinkapi',
    cmdclass = {'build_ext': build_ext},
    ext_modules = ext_modules
)
