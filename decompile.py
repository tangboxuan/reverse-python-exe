# compatible with both Python 2 and Python 3

import pefile 
import marshal
import os
import platform
import re
import sys
from utilities import generatePycHeader, pyc2py
from magic import magic_word_to_version
from pyinstxtractor import PyInstArchive
from clean import clean

pythonVersion = platform.python_version()

def get_rsrc(pe, name):
    for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if str(resource_type.name) != name :
            continue
        for resource_id in resource_type.directory.entries: 
            if not hasattr(resource_id, 'directory'):
                continue
            entry = resource_id.directory.entries[0]
            rsrc = pe.get_data(entry.data.struct.OffsetToData, entry.data.struct.Size)
            return rsrc 
    return None

def check_py2exe_pyversion(pe):
    peVersion = re.findall(b"python[0-9][0-9]", pe.__data__)
    if len(set(peVersion)) == 1:
        exeVersion = '.'.join(c for c in str(peVersion[0]) if c.isdigit())
        if not pythonVersion.startswith(exeVersion):
            print("Python " + exeVersion + " required")
            print("[!] Please switch your Python version")
            return False
        else:
            print("Exe compiled using Python {}".format(exeVersion))
            return True
    else:
        if not pythonVersion.startswith('2'):
            print("Python 2 required")
            return False
        else:
            print("Exe probably compiled using Python 2")
            return True

def exe2py(filename):
    pe = pefile.PE(filename)
    try:
        pe.DIRECTORY_ENTRY_RESOURCE
    except AttributeError:
        print("{} is not compiled from Python".format(filename))
        return False
        
    # py2exe
    # adapted from https://www.mandiant.com/resources/deobfuscating-python
    rsrc = get_rsrc(pe, "PYTHONSCRIPT")
    if rsrc != None and rsrc[:4] == b"\x12\x34\x56\x78":
        print("{} compiled with py2exe".format(filename))
        if not check_py2exe_pyversion(pe):
            return False
        offset = rsrc[0x010:].find(b"\x00") 
        if offset >= 0:
            data = rsrc[0x10 + offset + 1:]
            py2exeCode = marshal.loads(data)[-1]
            cleanCode = clean(py2exeCode)

            pycfilename = py2exeCode.co_filename + 'c'
            try:
                with open(pycfilename, "wb") as pyc:
                    pyc.write(generatePycHeader())
                    marshaled_code = marshal.dumps(cleanCode)
                    pyc.write(marshaled_code)
                pyc2py(pycfilename, py2exeCode.co_filename)
            finally:
                os.remove(pycfilename)
            print("Successfully decompiled file at output/{}".format(py2exeCode.co_filename))
            return True
        else:
            print("Failed to find end of header")
            return False
    
    # pyinstaller
    arch = PyInstArchive(filename)
    if arch.open():
        if arch.checkFile():
            print("{} compiled with pyinstaller".format(filename))
            pyinstallerCheck = arch.getCArchiveInfo()
            if pyinstallerCheck == 1:
                arch.parseTOC()
                arch.extractFiles()
                arch.close()
                return True
            elif pyinstallerCheck == -1:
                # Wrong python version
                return False
            else:
                # Not a pyinstaller file
                pass
        arch.close()

    # cx_freeze
    if re.search("Unable to change DLL search path", pe.__data__):
        print("{} compiled with cx_freeze.".format(filename))
        print("Run uncompyle6 on every file ending with _main_.pyc in lib\library.zip")
        return True

    # others
    print("{} is possibly compiled from Python, but not with py2exe, pyinstaller or cx_freeze".format(filename))
    return False

def try_decompile(filename):
    try:
        with open(filename, 'rb') as f:
            magic = f.read(2)
            if magic == b'MZ':
                # exe file
                print("{} is an exe file".format(filename))
                return exe2py(filename)

            try:
                pycVersion = magic_word_to_version(magic)
                # pyc file
                print("{} is a pyc file".format(filename))
                if pycVersion == sys.version_info[0:2]:
                    pyc2py(filename, "decompiled.py")
                    print("Successfully decompiled file at output/decompiled.py")
                    return True
                print("Python {}.{} required".format(pycVersion[0], pycVersion[1]))
                print("[!] Please switch your Python version")
                return False

            except KeyError:
                print("{} is not a exe or pyc file".format(filename))
                return False

    except FileNotFoundError:
        print("File {} not found".format(filename))
        return False

if __name__ == "__main__":
    if not os.path.exists("output"):
        os.mkdir("output")
    try:
        FileNotFoundError
    except NameError:
        FileNotFoundError = OSError

    files = ["exe_files/py2exe37_3line.exe"]
    # files = ["exe_files/pyinstaller37.exe"]
    # files = ["pyc_files/helloworld37.pyc"]
    # files = os.listdir("input")
    # files = ['input/' + f for f in files]
    for file in files:
        print('#' * 70)
        print("Decompiling {}...".format(file))
        if not try_decompile(file):
            print("Failed to decompile {}".format(file))