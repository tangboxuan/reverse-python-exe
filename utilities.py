import sys
from uncompyle6.main import decompile_file

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

def pyc2py(filename, output):
    with open("output/"+output, "w") as fo:
        decompile_file(filename, outstream=fo)

def writepyc(filename, data):
    with open(filename, "wb") as pyc:
        pyc.write(generatePycHeader())
        pyc.write(data)