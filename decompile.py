# compatible with both Python 2 and Python 3

import pefile 
import marshal
import os
import platform
import re
from uncompyle6.main import decompile_file
from pyinstxtractor import PyInstArchive, generatePycHeader
from clean import clean

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
    pythonVersion = platform.python_version()
    peVersion = re.findall(b"python[0-9][0-9]", pe.__data__)
    if len(set(peVersion)) == 1:
        exeVersion = '.'.join(c for c in str(peVersion[0]) if c.isdigit())
        if not pythonVersion.startswith(exeVersion):
            print("Python " + exeVersion + " required")
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

def exe2py(fileName):
    try:
        pe = pefile.PE(fileName)
    except FileNotFoundError:
        print("File {} not found".format(fileName))
        return False

    try:
        pe.DIRECTORY_ENTRY_RESOURCE
    except AttributeError:
        print("Not a python file")
        return False
        
    # py2exe
    # adapted from https://www.mandiant.com/resources/deobfuscating-python
    rsrc = get_rsrc(pe, "PYTHONSCRIPT")
    if rsrc != None and rsrc[:4] == b"\x12\x34\x56\x78":
        print("{} compiled with py2exe.".format(fileName))
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
                with open("output/"+py2exeCode.co_filename, "w") as fo:
                    decompile_file(pycfilename, fo)
            finally:
                os.remove(pycfilename)
            print("Successfully decompiled file at output/{}".format(py2exeCode.co_filename))
            return True
        else:
            print("Failed to find end of header")
            return False
    
    # pyinstaller
    arch = PyInstArchive(fileName)
    if arch.open():
        if arch.checkFile():
            print("{} compiled with pyinstaller.".format(fileName))
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
        print("{} compiled with cx_freeze.".format(fileName))
        print("Run uncompyle6 on every file ending with _main_.pyc in lib\library.zip")
        return True

    # others
    print("Exe file not from py2exe, PyInstall or cx_freeze")
    return False

if __name__ == "__main__":
    if not os.path.exists("output"):
        os.mkdir("output")
    try:
        FileNotFoundError
    except NameError:
        FileNotFoundError = OSError

    files = ["exe_files/khaki.exe"]
    # files = os.listdir("input")
    for file in files:
        print('#' * 70)
        if not exe2py(file):
            print("Failed to decompile {}".format(file))