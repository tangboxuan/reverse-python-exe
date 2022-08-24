import sys
import os
from uncompyle6.main import decompile

options = {}
options["debug"] = False
options["output"] = "output"

# imp is deprecated in Python3 in favour of importlib
if sys.version_info.major == 3:
    from importlib.util import MAGIC_NUMBER
    pyc_magic = MAGIC_NUMBER
else:
    import imp
    pyc_magic = imp.get_magic()

def generatePycHeader():
    header = pyc_magic
    if sys.version_info >= (3, 7):
        header += b'\0' * 12
    else:
        header += b'\0' * 4
        if sys.version_info >= (3, 3):
            header += b'\0' * 4
    return header

headerlength = len(generatePycHeader())

def co2py(co, outputname=None, outstream=None):
    if not outstream:
        if not os.path.exists(options["output"]):
            os.mkdir(options["output"])
        with open("{}/{}".format(options["output"], outputname), "w") as fo:
            decompile(None, co, fo)
    else:
        decompile(None, co, outstream)

# not currently used
# def writepyc(filename, data):
#     with open(filename, "wb") as pyc:
#         pyc.write(generatePycHeader())
#         pyc.write(data)