from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext
import glob, os

ext_modules = [
Extension("webui",  ["webui.py"]),
]

setup(
    name = 'huaweihilink',
    cmdclass = {'build_ext': build_ext},
    ext_modules = ext_modules
)


#delete C sources
for sourceFile in glob.glob("*.c"):
    os.remove(sourceFile)