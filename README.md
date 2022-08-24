# Reverse Python Exe (repyexe)

[![PyPi version](https://badgen.net/pypi/v/repyexe/)](https://pypi.org/project/repyexe)
[![PyPI pyversions](https://img.shields.io/pypi/pyversions/repyexe.svg)](https://pypi.org/project/repyexe)

## Description

Reverse Engineer Windows executable file compiled using Python.

## Usage

```
$ repyexe <exe_files and pyc_files>
```
```
from repyexe.decompile import decompile_exe

decompile_exe("samples/khaki.exe")
```
The version of Python used must be the same minor version as the one used to compile the file. If a different one is chosen, the script will exit with a message telling you which version to use. Use pyenv or something similar to switch your Python version.

For CX_Freeze files, the Python code is not located within the exe file but in pyc files in lib\library.zip, which needs to be manually extracted (using tools like uncompyle6).

## Background

This script aims to automate the reverse engineering of malware for analysis as much as possible.

Most of the Python executable files are compiled using Py2exe, PyInstaller or CX_Freeze. While this script aims to decompile any exe file, it is currently limited to only those compiled using these 3 libraries. A warning will be shown for exe files that do not match the signatures of files compiled using these libraries.

This script can also bypass the following deobsfucation techniques (only enabled on Py2exe):
- ``` NOP, ROT_TWO, ROT_THREE, LOAD_CONST & POP_TOP ```
- ``` EXTENDED_ARG ```

## Supported Files

Python <= 3.7  
Limited support for Python 3.8

Tested on files listed in [tested.md](https://github.com/tangboxuan/reverse-python-exe/blob/main/tested.md)

-  Python 2 using Py2exe
-  Python 3 using Py2exe
-  Python 2 using Py2exe with obsfucation
-  Python 3 using Py2exe with obsfucation
-  Python 2 using PyInstaller
-  Python 3 using PyInstaller 
-  Python 2 using PyInstaller --onefile
-  Python 3 using PyInstaller --onefile
-  Python 3 using CX_Freeze 

## Known Issues

1. Some ```JUMP``` instructions to ```EXTENDED_ARG``` instructions result in an error in uncompyle6's ifelsestmt.py file. Make the following [changes](https://github.com/tangboxuan/python-uncompyle6/commit/81633b3c1c3ae49120c755bd3ddfbc80ed452633) to the file.

## TODO

- Also support folders created by the 3 libraries (which would also automate the reverse engineering of files created by CX_Freeze)

## Requirements

- uncompyle6
- pefile

## Credits

1. Repo: [PyInstaller Extractor](https://github.com/extremecoders-re/pyinstxtractor) by Extreme Coders
1. Repo: [bytecode_graph](https://github.com/mandiant/flare-bytecode_graph) by Joshua Homan, Mandiant
1. Article: [Deobsfuscating Python Bytecode](https://www.mandiant.com/resources/deobfuscating-python) by Joshua Homan, Mandiant