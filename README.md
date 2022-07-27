# REpyexe

## Description

This script aims to decompile any Windows executable file compiled using Python into the original Python file.

## Supported Files

- [x] Python 2 using Py2exe
- [x] Python 3 using Py2exe
- [x] Python 2 using PyInstaller
- [x] Python 3 using PyInstaller 
- [x] Python 2 using PyInstaller --onefile
- [x] Python 3 using PyInstaller --onefile
- [x] Python 3 using CX_Freeze 

## Usage

```
python decompile.py <exe_file>
```
The version of Python used must be the same minor version as the one used to compile the file. If a different one is chosen, the script will exit with a message telling you which version to use. Use pyenv or something similar to switch your Python version.

For CX_Freeze files, the Python code is not located within the exe file but in pyc files in lib\library.zip, which needs to be manually extracted.

## Background

Most of the Python executable files out there are compiled using Py2exe, PyInstaller or CX_Freeze. While this script aims to decompile any exe file, it is currently limited to only those compiled using these 3 libraries.

## Files

- exe_files/py2exe37.exe: Hello World compiled using Py2exe in 3.7.9
- exe_files/py2exe27.exe: Hello World compiled using Py2exe in 2.7.18
- exe_files/pyinstaller37.exe: Hello World compiled using PyInstaller in 3.7.9 on 64-bit Windows
- exe_files/pyinstaller27.exe: Hello World compiled using PyInstaller in 2.7.18 on 64-bit Windows
- exe_files/pyinstaller37_onefile.exe: Hello World compiled using PyInstaller in 2.7.18 on 64-bit Windows with --onefile flag
- exe_files/pyinstaller27_onefile.exe: Hello World compiled using PyInstaller in 2.7.18 on 64-bit Windows with --onefile flag
- exe_files/cxfreeze37.exe: Hello World compiled using CX_Freeze in 3.7.9 on 64-bit Windows