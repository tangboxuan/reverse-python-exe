# REpyexe

## Description

This script aims to decompile any Windows executable file compiled using Python into the original Python file. This will automate the reverse engineering of malware for analysis.

## Supported Files

- [x] Python 2 using Py2exe
- [x] Python 3 using Py2exe
- [x] Python 2 using Py2exe with obsfucation
- [ ] Python 3 using Py2exe with obsfucation
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

For CX_Freeze files, the Python code is not located within the exe file but in pyc files in lib\library.zip, which needs to be manually extracted (using tools like uncompyle6).

## Background

Most of the Python executable files are compiled using Py2exe, PyInstaller or CX_Freeze. While this script aims to decompile any exe file, it is currently limited to only those compiled using these 3 libraries. A warning will be shown for exe files that do not match the signatures of files compiled using these libraries.

This script also aims to deobsfuscate Python bytecode containing the following obsfucation:
- ``` NOP, ROT_TWO, ROT_THREE, LOAD_CONST & POP_TOP ```

## exe Files

1. trilog.exe: ICS Malware compiled using Py2exe in 2.7
1. fidler.exe: Flare-On 7 (2020) Challenge 1 compiled using PyInstaller in 3.8
1. wopr.exe: Flare-On 6 (2019) Challenge 7 compiled using PyInstaller in 3.7
1. khaki.exe: Flare-On 3 (2016) Challenge 6 compiled using Py2exe in 2.7 and obsfucated
1. py2exe37.exe: Hello World compiled using Py2exe in 3.7.9
1. py2exe27.exe: Hello World compiled using Py2exe in 2.7.18
1. pyinstaller37.exe: Hello World compiled using PyInstaller in 3.7.9 on 64-bit Windows
1. pyinstaller27.exe: Hello World compiled using PyInstaller in 2.7.18 on 64-bit Windows
1. pyinstaller37_onefile.exe: Hello World compiled using PyInstaller in 2.7.18 on 64-bit Windows with --onefile flag
1. pyinstaller27_onefile.exe: Hello World compiled using PyInstaller in 2.7.18 on 64-bit Windows with --onefile flag
1. cxfreeze37.exe: Hello World compiled using CX_Freeze in 3.7.9 on 64-bit Windows

## TO DO

- Deobfuscate Python bytecode containing ``` NOP, ROT_TWO, ROT_THREE, LOAD_CONST & POP_TOP ``` obsfucation in Python 3
- Also support folders created by the 3 libraries (which would also automate the reverse engineering of files created by CX_Freeze)
- Publish library

## Credits

1. Repo: [PyInstaller Extractor](https://github.com/extremecoders-re/pyinstxtractor) by Extreme Coders
1. Repo: [bytecode_graph](https://github.com/mandiant/flare-bytecode_graph) by Joshua Homan, Mandiant
1. Article: [Deobsfuscating Python Bytecode](https://www.mandiant.com/resources/deobfuscating-python) by Joshua Homan, Mandiant