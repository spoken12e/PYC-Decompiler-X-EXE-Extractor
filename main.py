import os
import time
import struct
import zlib
import marshal
import sys
import requests
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
from tkinterdnd2 import TkinterDnD, DND_FILES
import dis
import types
import logging
import uncompyle6
import subprocess
import multiprocessing
import autopep8

logging.basicConfig(filename='decompiler.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class PyInstExtractorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PYC DECOMPILER X EXTRACTOR")
        self.root.geometry("700x600")
        self.root.resizable(False, False)
        self.root.configure(bg="#1E1E1E")
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TFrame", background="#1E1E1E")
        self.style.configure("TLabel", background="#1E1E1E", foreground="#D8DEE9", font=("Helvetica", 14))
        self.style.configure("TButton", background="#333333", foreground="#D8DEE9", font=("Helvetica", 12))
        self.style.configure("TEntry", background="#333333", foreground="#D8DEE9", font=("Helvetica", 12))
        self.style.configure("TScrollbar", background="#333333")
        self.style.configure("TCheckbutton", background="#1E1E1E", foreground="#D8DEE9", font=("Helvetica", 12))
        self.webhook_enabled = tk.BooleanVar(value=False)
        self.save_txt_enabled = tk.BooleanVar(value=False)
        self.use_hyv2 = tk.BooleanVar(value=False)
        self.create_widgets()

    def create_widgets(self):
        self.frame = ttk.Frame(self.root)
        self.frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.title_label = ttk.Label(self.frame, text="Pyc Decompiler X Extractor", font=("Helvetica", 18, "bold"))
        self.title_label.pack(pady=10)
        self.description_label = ttk.Label(self.frame, text="Drag and drop a .exe or .pyc file to extract or decompile it.", font=("Helvetica", 12))
        self.description_label.pack(pady=5)
        self.info_label = ttk.Label(self.frame, text="Made by spoken12e", font=("Helvetica", 10))
        self.info_label.pack(pady=5)
        self.log_area = scrolledtext.ScrolledText(self.frame, wrap=tk.WORD, state='disabled', bg="#333333", fg="#D8DEE9", insertbackground="#D8DEE9")
        self.log_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.options_frame = ttk.Frame(self.frame)
        self.options_frame.pack(fill=tk.X, pady=5)
        self.webhook_switch = ttk.Checkbutton(self.options_frame, text="Send decompiled .pyc to webhook", variable=self.webhook_enabled, command=self.toggle_webhook_entry)
        self.webhook_switch.pack(side=tk.LEFT, padx=5)
        self.save_txt_switch = ttk.Checkbutton(self.options_frame, text="Save decompiled .pyc as .txt", variable=self.save_txt_enabled)
        self.save_txt_switch.pack(side=tk.LEFT, padx=5)
        self.hyv2_switch = ttk.Checkbutton(self.options_frame, text="Use hyv2 to decompile", variable=self.use_hyv2)
        self.hyv2_switch.pack(side=tk.LEFT, padx=5)
        self.webhook_entry = ttk.Entry(self.frame, width=50, state='disabled')
        self.webhook_entry.pack(pady=5)
        self.clear_button = ttk.Button(self.frame, text="Clear Console", command=self.clear_console)
        self.clear_button.pack(pady=5)
        self.frame.drop_target_register(DND_FILES)
        self.frame.dnd_bind('<<Drop>>', self.on_drop)

    def clear_console(self):
        self.log_area.config(state='normal')
        self.log_area.delete(1.0, tk.END)
        self.log_area.config(state='disabled')

    def toggle_webhook_entry(self):
        if self.webhook_enabled.get():
            self.webhook_entry.config(state='normal')
        else:
            self.webhook_entry.config(state='disabled')

    def on_drop(self, event):
        file_path = event.data.strip('{}')
        if file_path.endswith('.exe') or file_path.endswith('.pyc'):
            self.log_area.config(state='normal')
            self.log_area.insert(tk.END, f"Processing file: {file_path}\n")
            self.log_area.config(state='disabled')
            if file_path.endswith('.exe'):
                self.extract_file(file_path)
            else:
                self.decompile_pyc(file_path)
        else:
            messagebox.showerror("Error", "Please drop a valid .exe or .pyc file")

    def extract_file(self, file_path):
        arch = PyInstArchive(file_path)
        if arch.open():
            if arch.checkFile():
                if arch.getCArchiveInfo():
                    arch.parseTOC()
                    arch.extractFiles()
                    arch.close()
                    self.log_area.config(state='normal')
                    self.log_area.insert(tk.END, "[+] Successfully extracted pyinstaller archive\n")
                    self.log_area.insert(tk.END, "You can now use a python decompiler on the pyc files within the extracted directory\n")
                    self.log_area.config(state='disabled')
                    return
            arch.close()

    def decompile_pyc(self, file_path):
        webhook_url = self.webhook_entry.get().strip() if self.webhook_enabled.get() else None
        if self.use_hyv2.get():
            decompiled_code = self.decompile_with_hyv2(file_path)
        else:
            decompiled_code = self.decompile_with_pylingual(file_path)
        if decompiled_code:
            if self.save_txt_enabled.get():
                save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
                if save_path:
                    with open(save_path, "w") as f:
                        f.write(decompiled_code)
                    self.log_area.config(state='normal')
                    self.log_area.insert(tk.END, f"[+] Decompiled source code saved to {save_path}\n")
                    self.log_area.config(state='disabled')
            if webhook_url:
                requests.post(webhook_url, files={"file": ("decompiled.py", decompiled_code)})
                self.log_area.config(state='normal')
                self.log_area.insert(tk.END, "[+] Decompiled source code sent to webhook\n")
                self.log_area.config(state='disabled')

    def decompile_with_hyv2(self, file_path):
        try:
            with open(file_path, "rb") as f:
                magic = f.read(4)
                version = get_python_version(magic)
                if version:
                    python_version = version[0] + version[1] / 10
                    f.seek(8 if python_version >= 3.3 else 4)
                    bytecode = f.read()
                    decompiled_code = decompile_bytecode(bytecode, python_version)
                    return decompiled_code
                else:
                    return "Unsupported Python version"
        except Exception as e:
            return f"Error during decompilation: {e}"

    def decompile_with_pylingual(self, file_path):
        url = "https://api.pylingual.io/upload"
        headers = {
            "user-agent": "mozilla/5.0 (windows nt 10.0; win64; x64; rv:134.0) gecko/20100101 firefox/134.0",
            "accept": "*/*",
            "accept-language": "en-us,en;q=0.5",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "priority": "u=4"
        }
        try:
            with open(file_path, "rb") as file:
                files = {
                    "file": ("decompiled.pyc", file, "application/octet-stream"),
                    "fileName": (None, "decompiled.pyc")
                }
                response = requests.post(url, headers=headers, files=files)
                success = response.json().get('success')
                trackid = response.json().get('identifier')
                if not success:
                    return "Failed to load the decompiler"
                while True:
                    res = requests.get(f"https://api.pylingual.io/get_progress?identifier={trackid}")
                    stage = res.json().get('stage')
                    if stage == 'done':
                        break
                    time.sleep(2)
                final_res = requests.get(f"https://api.pylingual.io/view_chimera?identifier={trackid}")
                file_content = final_res.json().get("editor_content", {}).get("file_raw_python", {}).get("editor_content")
                if file_content:
                    return "\n".join([line for line in file_content.split("\n") if not line.strip().startswith("#")])
                else:
                    return "Failed to retrieve decompiled content"
        except Exception as e:
            return f"Error during decompilation: {e}"

def get_python_version(magic_number):
    version_map = {
        b'\x33\x0d\x0d\x0a': (3, 6),
        b'\x42\x0d\x0d\x0a': (3, 7),
        b'\x52\x0d\x0d\x0a': (3, 8),
        b'\x62\x0d\x0d\x0a': (3, 9),
        b'\x72\x0d\x0d\x0a': (3, 10),
        b'\x82\x0d\x0d\x0a': (3, 11),
        b'\x92\x0d\x0d\x0a': (3, 12),
    }
    return version_map.get(magic_number)

def decompile_bytecode(bytecode, python_version):
    try:
        code_obj = marshal.loads(bytecode)
        return disassemble(code_obj, python_version)
    except Exception as e:
        return f"Error loading bytecode: {e}"

def disassemble(code_obj, python_version, level=0):
    output = ""
    indent = "  " * level
    output += f"{indent}Code object: {code_obj.co_name}\n"
    output += f"{indent}  Flags: {code_obj.co_flags}\n"
    output += f"{indent}  Constants: {code_obj.co_consts}\n"
    output += f"{indent}  Names: {code_obj.co_names}\n"
    output += f"{indent}  Variables: {code_obj.co_varnames}\n"
    output += f"{indent}  Free variables: {code_obj.co_freevars}\n"
    output += f"{indent}  Cell variables: {code_obj.co_cellvars}\n"
    for instr in dis.get_instructions(code_obj):
        arg_val = instr.argval
        if python_version >= 3 and instr.opname in dis.hasconst:
            try:
                arg_val = repr(code_obj.co_consts[instr.arg])
            except IndexError:
                pass
        output += f"{indent}  {instr.offset:4} {instr.opname:<20} {arg_val if instr.arg is not None else ''}\n"
    for const in code_obj.co_consts:
        if isinstance(const, types.CodeType):
            output += disassemble(const, python_version, level + 1)
    return output

class PyInstArchive:
    PYINST20_COOKIE_SIZE = 24
    PYINST21_COOKIE_SIZE = 24 + 64
    MAGIC = b'MEI\014\013\012\013\016'

    def __init__(self, path):
        self.filePath = path
        self.pycMagic = b'\0' * 4
        self.barePycList = []

    def open(self):
        try:
            self.fPtr = open(self.filePath, 'rb')
            self.fileSize = os.stat(self.filePath).st_size
        except:
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
            return False
        self.fPtr.seek(self.cookiePos + self.PYINST20_COOKIE_SIZE, os.SEEK_SET)
        if b'python' in self.fPtr.read(64).lower():
            self.pyinstVer = 21
        else:
            self.pyinstVer = 20
        return True

    def getCArchiveInfo(self):
        try:
            if self.pyinstVer == 20:
                self.fPtr.seek(self.cookiePos, os.SEEK_SET)
                (magic, lengthofPackage, toc, tocLen, pyver) = struct.unpack('!8siiii', self.fPtr.read(self.PYINST20_COOKIE_SIZE))
            elif self.pyinstVer == 21:
                self.fPtr.seek(self.cookiePos, os.SEEK_SET)
                (magic, lengthofPackage, toc, tocLen, pyver, pylibname) = struct.unpack('!8sIIii64s', self.fPtr.read(self.PYINST21_COOKIE_SIZE))
        except:
            return False
        self.pymaj, self.pymin = (pyver//100, pyver%100) if pyver >= 100 else (pyver//10, pyver%10)
        tailBytes = self.fileSize - self.cookiePos - (self.PYINST20_COOKIE_SIZE if self.pyinstVer == 20 else self.PYINST21_COOKIE_SIZE)
        self.overlaySize = lengthofPackage + tailBytes
        self.overlayPos = self.fileSize - self.overlaySize
        self.tableOfContentsPos = self.overlayPos + toc
        self.tableOfContentsSize = tocLen
        return True

    def parseTOC(self):
        self.fPtr.seek(self.tableOfContentsPos, os.SEEK_SET)
        self.tocList = []
        parsedLen = 0
        while parsedLen < self.tableOfContentsSize:
            (entrySize, ) = struct.unpack('!i', self.fPtr.read(4))
            nameLen = struct.calcsize('!iIIIBc')
            (entryPos, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name) = struct.unpack('!IIIBc{0}s'.format(entrySize - nameLen), self.fPtr.read(entrySize - 4))
            try:
                name = name.decode("utf-8").rstrip("\0")
            except UnicodeDecodeError:
                name = str(uniquename())
            if name.startswith("/"):
                name = name.lstrip("/")
            if len(name) == 0:
                name = str(uniquename())
            self.tocList.append(CTOCEntry(self.overlayPos + entryPos, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name))
            parsedLen += entrySize

    def _writeRawData(self, filepath, data):
        nm = filepath.replace('\\', os.path.sep).replace('/', os.path.sep).replace('..', '__')
        nmDir = os.path.dirname(nm)
        if nmDir != '' and not os.path.exists(nmDir):
            os.makedirs(nmDir)
        with open(nm, 'wb') as f:
            f.write(data)

    def extractFiles(self):
        extractionDir = os.path.join(os.getcwd(), os.path.basename(self.filePath) + '_extracted')
        if not os.path.exists(extractionDir):
            os.mkdir(extractionDir)
        os.chdir(extractionDir)
        for entry in self.tocList:
            self.fPtr.seek(entry.position, os.SEEK_SET)
            data = self.fPtr.read(entry.cmprsdDataSize)
            if entry.cmprsFlag == 1:
                try:
                    data = zlib.decompress(data)
                except zlib.error:
                    continue
                assert len(data) == entry.uncmprsdDataSize
            if entry.typeCmprsData == b'd' or entry.typeCmprsData == b'o':
                continue
            basePath = os.path.dirname(entry.name)
            if basePath != '':
                if not os.path.exists(basePath):
                    os.makedirs(basePath)
            if entry.typeCmprsData == b's':
                if self.pycMagic == b'\0' * 4:
                    self.barePycList.append(entry.name + '.pyc')
                self._writePyc(entry.name + '.pyc', data)
            elif entry.typeCmprsData == b'M' or entry.typeCmprsData == b'm':
                if data[2:4] == b'\r\n':
                    if self.pycMagic == b'\0' * 4:
                        self.pycMagic = data[0:4]
                    self._writeRawData(entry.name + '.pyc', data)
                else:
                    if self.pycMagic == b'\0' * 4:
                        self.barePycList.append(entry.name + '.pyc')
                    self._writePyc(entry.name + '.pyc', data)
            else:
                self._writeRawData(entry.name, data)
                if entry.typeCmprsData == b'z' or entry.typeCmprsData == b'Z':
                    self._extractPyz(entry.name)
        self._fixBarePycs()

    def _fixBarePycs(self):
        for pycFile in self.barePycList:
            with open(pycFile, 'r+b') as pycFile:
                pycFile.write(self.pycMagic)

    def _writePyc(self, filename, data):
        with open(filename, 'wb') as pycFile:
            pycFile.write(self.pycMagic)
            if self.pymaj >= 3 and self.pymin >= 7:
                pycFile.write(b'\0' * 4)
                pycFile.write(b'\0' * 8)
            else:
                pycFile.write(b'\0' * 4)
                if self.pymaj >= 3 and self.pymin >= 3:
                    pycFile.write(b'\0' * 4)
            pycFile.write(data)

    def _extractPyz(self, name):
        dirName = name + '_extracted'
        if not os.path.exists(dirName):
            os.mkdir(dirName)
        with open(name, 'rb') as f:
            pyzMagic = f.read(4)
            assert pyzMagic == b'PYZ\0'
            pyzPycMagic = f.read(4)
            if self.pycMagic == b'\0' * 4:
                self.pycMagic = pyzPycMagic
            elif self.pycMagic != pyzPycMagic:
                self.pycMagic = pyzPycMagic
            if self.pymaj != sys.version_info.major or self.pymin != sys.version_info.minor:
                return
            (tocPosition, ) = struct.unpack('!i', f.read(4))
            f.seek(tocPosition, os.SEEK_SET)
            try:
                toc = marshal.load(f)
            except:
                return
            if type(toc) == list:
                toc = dict(toc)
            for key in toc.keys():
                (ispkg, pos, length) = toc[key]
                f.seek(pos, os.SEEK_SET)
                fileName = key
                try:
                    fileName = fileName.decode('utf-8')
                except:
                    pass
                fileName = fileName.replace('..', '__').replace('.', os.path.sep)
                if ispkg == 1:
                    filePath = os.path.join(dirName, fileName, '__init__.pyc')
                else:
                    filePath = os.path.join(dirName, fileName + '.pyc')
                fileDir = os.path.dirname(filePath)
                if not os.path.exists(fileDir):
                    os.makedirs(fileDir)
                try:
                    data = f.read(length)
                    data = zlib.decompress(data)
                except:
                    open(filePath + '.encrypted', 'wb').write(data)
                else:
                    self._writePyc(filePath, data)

class CTOCEntry:
    def __init__(self, position, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name):
        self.position = position
        self.cmprsdDataSize = cmprsdDataSize
        self.uncmprsdDataSize = uncmprsdDataSize
        self.cmprsFlag = cmprsFlag
        self.typeCmprsData = typeCmprsData
        self.name = name

def uniquename():
    import uuid
    return uuid.uuid4().hex

if __name__ == '__main__':
    root = TkinterDnD.Tk()
    app = PyInstExtractorGUI(root)
    root.mainloop()
