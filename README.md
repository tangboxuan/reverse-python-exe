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

-  Python 2 using Py2exe
-  Python 3 using Py2exe
-  Python 2 using Py2exe with obsfucation
-  Python 3 using Py2exe with obsfucation
-  Python 2 using PyInstaller
-  Python 3 using PyInstaller 
-  Python 2 using PyInstaller --onefile
-  Python 3 using PyInstaller --onefile
-  Python 3 using CX_Freeze 

## Tested on
1. Evilnum Pyvil RAT compiled using Py2exe in 3.7

    | MD5 | SHA256 |
    | :---: | :---: |
    | 0fff692652ec73d4f17438284a720224 | 5b159b58ee73c3330b1599913c6a7f66e4aaecad536223474fc8b6bb7700cd2f
    | 14d9d03cbb892bbbf9939ee8fffdd2b5 | 824626e09bffec0ee539d0165df0d9a1ef668d32d8fcccf13708d24e108d7cf9
    | b4183e52fb807689140ed5aa20808700 | 3fb323ad790d26fa319577e179190c1b25840a2aeffbe11072cce48f1bafde89 |
    | bb2113989478db0ae1dfbf6450079252 | d0c313a1983498abadb5ff36cb66aca5d2fc8893cbd6d40f9a85c6274fe5c8a3
    | d3947c239a07090deb7d4a9d21d68813 | 5988265627e2935865a2255f90d10c83b54046137834cb4c81748f2221971a4b | 

1. Triton ICS Malware compiled using Py2exe in 2.7

    | MD5 | SHA256 |
    | :---: | :---: |
    | 6c39c3f4a08d3d78f2eb973a94bd7718 | e8542c07b2af63ee7e72ce5d97d91036c5da56e2b091aa2afe737b224305d230 |

1. Example exe and pyc files found in /samples

## TODO
- Fix ```Exception in ifelsestmt '>' not supported between instances of 'str' and 'int'``` error
- Also support folders created by the 3 libraries (which would also automate the reverse engineering of files created by CX_Freeze)
- Publish library

## Requirements

- uncompyle6
- pefile

## Credits

1. Repo: [PyInstaller Extractor](https://github.com/extremecoders-re/pyinstxtractor) by Extreme Coders
1. Repo: [bytecode_graph](https://github.com/mandiant/flare-bytecode_graph) by Joshua Homan, Mandiant
1. Article: [Deobsfuscating Python Bytecode](https://www.mandiant.com/resources/deobfuscating-python) by Joshua Homan, Mandiant