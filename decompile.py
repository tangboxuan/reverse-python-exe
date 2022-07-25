# compatible with both Python 2 and Python 3

import pefile 
import sys, dis, marshal, re, os, subprocess, platform
from uncompyle6.main import decompile

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
    dll = str(subprocess.Popen(command, shell=True, stdout=subprocess.PIPE).stdout.read())
    exeVersion = '.'.join(dll.split('.')[0][-2:])
    if not pythonVersion.startswith(exeVersion):
        print("Python " + exeVersion + " required")
        sys.exit()

if __name__ == "__main__":
    # fileName = sys.argv[1]
    if platform.python_version().startswith("2"): 
        fileName = "exe_files/helloworld_py2exe_2.exe"
    else:
        fileName = "exe_files/helloworld_py2exe.exe"
    check_python_version(fileName)
    pe = pefile.PE(fileName)
    rsrc = get_rsrc(pe, "PYTHONSCRIPT")

    if rsrc != None and rsrc[:4] == b"\x12\x34\x56\x78":
        offset = rsrc[0x010:].find(b"\x00") 
        if offset >= 0:
            data = rsrc[0x10 + offset + 1:]
            py2exeCode = marshal.loads(data)[-1]
            # dis.dis(py2exeCode)
            decompile(None, py2exeCode, sys.stdout)
            print()
        else:
            print("Failed to find end of header")
    else:
        print("Failed to find PYTHONSCRIPT resource")