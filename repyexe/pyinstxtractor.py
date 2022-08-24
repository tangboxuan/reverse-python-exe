# modified from https://github.com/extremecoders-re/pyinstxtractor
# by Extreme Coders

from __future__ import print_function
import marshal
import os
import struct
import traceback
import zlib
import sys
import dis
from uuid import uuid4 as uniquename
from .utilities import co2py, options
from .clean import clean

class CTOCEntry:
    def __init__(self, position, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name):
        self.position = position
        self.cmprsdDataSize = cmprsdDataSize
        self.uncmprsdDataSize = uncmprsdDataSize
        self.cmprsFlag = cmprsFlag
        self.typeCmprsData = typeCmprsData
        self.name = name


class PyInstArchive:
    PYINST20_COOKIE_SIZE = 24           # For pyinstaller 2.0
    PYINST21_COOKIE_SIZE = 24 + 64      # For pyinstaller 2.1+
    MAGIC = b'MEI\014\013\012\013\016'  # Magic number which identifies pyinstaller

    def __init__(self, path):
        self.filePath = path


    def open(self):
        try:
            self.fPtr = open(self.filePath, 'rb')
            self.fileSize = os.stat(self.filePath).st_size
        except:
            print('[!] Error: Could not open {0}'.format(self.filePath))
            return False
        return True


    def close(self):
        try:
            self.fPtr.close()
        except:
            pass


    def checkFile(self):
        searchChunkSize = 8192
        endPos = self.fileSize
        self.cookiePos = -1

        if endPos < len(self.MAGIC):
            print('[!] Error : File is too short or truncated')
            return False

        while True:
            startPos = endPos - searchChunkSize if endPos >= searchChunkSize else 0
            chunkSize = endPos - startPos

            if chunkSize < len(self.MAGIC):
                break

            self.fPtr.seek(startPos, os.SEEK_SET)
            data = self.fPtr.read(chunkSize)

            offs = data.rfind(self.MAGIC)

            if offs != -1:
                self.cookiePos = startPos + offs
                break

            endPos = startPos + len(self.MAGIC) - 1

            if startPos == 0:
                break

        if self.cookiePos == -1:
            # print('[!] Error : Missing cookie, unsupported pyinstaller version or not a pyinstaller archive')
            return False

        self.fPtr.seek(self.cookiePos + self.PYINST20_COOKIE_SIZE, os.SEEK_SET)

        if b'python' in self.fPtr.read(64).lower():
            self.pyinstVer = 21     # pyinstaller 2.1+
        else:
            self.pyinstVer = 20     # pyinstaller 2.0

        return True


    def getCArchiveInfo(self):
        try:
            if self.pyinstVer == 20:
                self.fPtr.seek(self.cookiePos, os.SEEK_SET)

                # Read CArchive cookie
                (magic, lengthofPackage, toc, tocLen, pyver) = \
                struct.unpack('!8siiii', self.fPtr.read(self.PYINST20_COOKIE_SIZE))

            elif self.pyinstVer == 21:
                self.fPtr.seek(self.cookiePos, os.SEEK_SET)

                # Read CArchive cookie
                (magic, lengthofPackage, toc, tocLen, pyver, pylibname) = \
                struct.unpack('!8siiii64s', self.fPtr.read(self.PYINST21_COOKIE_SIZE))

        except:
            print('[!] Error : The file is not a pyinstaller archive')
            return 0, None

        self.pymaj, self.pymin = (pyver//100, pyver%100) if pyver >= 100 else (pyver//10, pyver%10)
        if sys.version_info[0] != self.pymaj or sys.version_info[1] != self.pymin:
            message = "Python {0}.{1} required".format(self.pymaj, self.pymin)
            print(message)
            print("[!] Please switch your Python version")
            return -1, message
        print("Exe compiled using Python {}.{}".format(self.pymaj, self.pymin))

        # Additional data after the cookie
        tailBytes = self.fileSize - self.cookiePos - (self.PYINST20_COOKIE_SIZE if self.pyinstVer == 20 else self.PYINST21_COOKIE_SIZE)
        
        # Overlay is the data appended at the end of the PE
        self.overlaySize = lengthofPackage + tailBytes
        self.overlayPos = self.fileSize - self.overlaySize
        self.tableOfContentsPos = self.overlayPos + toc
        self.tableOfContentsSize = tocLen

        return 1, None


    def parseTOC(self):
        # Go to the table of contents
        self.fPtr.seek(self.tableOfContentsPos, os.SEEK_SET)

        self.tocList = []
        parsedLen = 0

        # Parse table of contents
        while parsedLen < self.tableOfContentsSize:
            (entrySize, ) = struct.unpack('!i', self.fPtr.read(4))
            nameLen = struct.calcsize('!iiiiBc')

            (entryPos, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name) = \
            struct.unpack( \
                '!iiiBc{0}s'.format(entrySize - nameLen), \
                self.fPtr.read(entrySize - 4))

            name = name.decode('utf-8').rstrip('\0')
            if len(name) == 0:
                name = str(uniquename())
                print('[!] Warning: Found an unamed file in CArchive. Using random name {0}'.format(name))

            self.tocList.append( \
                                CTOCEntry(                      \
                                    self.overlayPos + entryPos, \
                                    cmprsdDataSize,             \
                                    uncmprsdDataSize,           \
                                    cmprsFlag,                  \
                                    typeCmprsData,              \
                                    name                        \
                                ))

            parsedLen += entrySize

    def extractFiles(self, outstream=None):

        written = []
        failure = []

        for entry in self.tocList:
            self.fPtr.seek(entry.position, os.SEEK_SET)
            data = self.fPtr.read(entry.cmprsdDataSize)

            if entry.cmprsFlag == 1:
                data = zlib.decompress(data)
                # Malware may tamper with the uncompressed size
                # Comment out the assertion in such a case
                assert len(data) == entry.uncmprsdDataSize # Sanity Check

            if entry.typeCmprsData == b's':
                # s -> ARCHIVE_ITEM_PYSOURCE
                # Entry point are expected to be python scripts
                outputname = "{}.py".format(entry.name)
                try:
                    co = marshal.loads(data)
                    cleanco = clean(co)

                    if options["debug"]:
                        dis.dis(cleanco)

                    co2py(cleanco, outputname=outputname, outstream=outstream)
                    print("Successfully decompiled file at output/{}".format(outputname))
                    written.append(outputname)
                except Exception:
                    traceback.print_exc()
                    print("Unable to decompile {}".format(outputname))
                    failure.append(outputname)
        
        totalsuccess = len(failure) == 0
        if written:
            if totalsuccess:
                print("Successfully decompiled all files")
            else:
                print("Successfully decompiled some files, follwing files not decompile:")
                print("\n".join(failure))
        message = " + ".join(written)
        if not totalsuccess:
            if message:
                message = "\n[!] Partial success: {}".format(message)
            message += "\n[!] Failure: {}".format(" + ".join(failure))
        return totalsuccess, message