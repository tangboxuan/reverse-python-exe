# compatible with both Python 2 and Python 3
# adapted from https://www.mandiant.com/resources/deobfuscating-python

import pefile 
import sys, dis, marshal, re, os, subprocess, platform
from uncompyle6.main import decompile
from pyinstxtractor import PyInstArchive

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

def check_python_version(filename):
    command = "strings " + fileName + " | grep \"^python[0-9][0-9].dll$\""
    pythonVersion = platform.python_version()
    dll = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE).stdout.read()
    if dll:
        exeVersion = '.'.join(str(dll).split('.')[0][-2:])
        if not pythonVersion.startswith(exeVersion):
            print("Python " + exeVersion + " required")
            sys.exit()
    else:
        if not pythonVersion.startswith('2'):
            print("Python 2 required")
            sys.exit()

if __name__ == "__main__":
    # fileName = sys.argv[1]
    fileName = "exe_files/helloworld_py2exe_2.exe"
    pe = pefile.PE(fileName)
    rsrc = get_rsrc(pe, "PYTHONSCRIPT")
    if rsrc != None and rsrc[:4] == b"\x12\x34\x56\x78":
        # py2exe file
        check_python_version(fileName)
        offset = rsrc[0x010:].find(b"\x00") 
        if offset >= 0:
            data = rsrc[0x10 + offset + 1:]
            py2exeCode = marshal.loads(data)[-1]
            # dis.dis(py2exeCode)
            decompile(None, py2exeCode, sys.stdout)
            print()
        else:
            print("Failed to find end of header")
            sys.exit(1)
        sys.exit()
    
    arch = PyInstArchive(fileName)
    if arch.open():
        if arch.checkFile():
            # PyInstaller file
            if arch.getCArchiveInfo():
                arch.parseTOC()
                arch.extractFiles()
                arch.close()
        arch.close()
        sys.exit()

    print("Exe file not from py2exe or PyInstaller")