# REpyexe

## Description

This script aims to decompile any Windows executable file compiled using Python into the original Python file.

## Supported Files

- [x] Python 2 using Py2exe
- [x] Python 3 using Py2exe
- [ ] Python 2 using PyInstaller
- [ ] Python 3 using PyInstaller 

## Usage

```
python decompile.py <exe_file>
```
The version of Python used must be the same minor version as the one used to compile the file. If a different one is chosen, the script will exit with a message telling you which version to use. Use pyenv or something similar to switch your Python version.

## Background

Most of the Python executable files out there are compiled using Py2exe or PyInstaller. While this script aims to decompile any exe file, it is currently limited to only those compiled using these 2 libraries.

## Files

- exe_files/helloworld_py2exe.exe: Hello World compiled using Py2exe in 3.7.9
- exe_files/helloworld_py2exe_2.exe: Hello World compiled using Py2exe in 2.7.18