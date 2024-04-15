import datetime
import os
from mmap import ACCESS_READ, mmap

import fitz  # install openpyxl
import pandas  # install PyMuPDF
from bs4 import BeautifulSoup
from docx2python import docx2python
from striprtf.striprtf import rtf_to_text

excluded_filenames = 'ChromeExtMalware.store'  # Excluded because of false positives


def get_printabletime():
    return datetime.datetime.now().strftime("%H:%M:%S")


class FileHandler:
    """
    FileHandler takes a file as input and deals with all file related parts.
    """
    def __init__(self, file_path):
        self.file_path = file_path

    def getfilesize(self):
        try:
            return os.path.getsize(self.file_path)
        except:
            return 0

    def getfilesize_printable(self):
        file_size = self.getfilesize()
        for unit in ['B', 'KB', 'MB', 'GB']:
            if file_size < 1024.0:
                break
            file_size /= 1024.0
        return f"{file_size:.{0}f}{unit}"

    def check_if_excluded(self, excluded_paths):
        for path in excluded_paths:
            if path in self.file_path:
                print(f"{get_printabletime()}: {self.file_path} is excluded due to exclusion path rule: {path}")
                return True

        if self.file_path.endswith(excluded_filenames):
            print(f"{get_printabletime()}: {self.file_path} is excluded due to exclusion file rule: {excluded_filenames}")
            return True
        return False

    def filecheck(self, inputfilesize):
        if not os.path.exists(self.file_path):
            print(f"{get_printabletime()}: {self.file_path} doesn't exist.")
            return True

        file_size = self.getfilesize()
        if file_size < 15:
            print(f"{get_printabletime()}: {self.file_path} is too small. Size: {str(file_size)}B")
            return True

        if file_size >= inputfilesize:
            print(f"{get_printabletime()}: {self.file_path} is too large. Size: {self.getfilesize_printable()}")
            return True

        return False

    def getfileextension(self):
        return os.path.splitext(self.file_path)[1]

    def getspecialfiledata(self):
        if self.getfileextension() == '.docx':
            return self.docxtobytes()

        if self.getfileextension() == '.html':
            return self.htmltobytes()

        if self.getfileextension() == '.pdf':
            return self.pdftobytes()

        if self.getfileextension() == '.rtf':
            return self.rtftobytes()

        if self.getfileextension() == '.xlsx':
            return self.xlsxtobytes()

    def docxtobytes(self):
        try:
            return bytes(docx2python(self.file_path).text, 'utf-8')
        except Exception as err:
            print(f"{get_printabletime()}: DOCX error - {self.file_path}: {err}")
            return False

    def htmltobytes(self):
        try:
            with open(self.file_path, 'rb') as file, mmap(file.fileno(), 0, access=ACCESS_READ) as mmapfile:
                soup = BeautifulSoup(mmapfile.read().decode('utf8', 'ignore'), 'html.parser')
                return bytes(soup.get_text(strip=True), 'utf8')
        except Exception as err:
            print(f"{get_printabletime()}: HTML error - {self.file_path}: {err}")
            return False

    def pdftobytes(self):
        try:
            pdf = fitz.open(self.file_path)
            pdftext = ""
            for page in pdf:
                pdftext += page.get_text()
            return bytes(pdftext, 'utf-8')
        except Exception as err:
            print(f"{get_printabletime()}: PDF error - {self.file_path}: {err}")
            return False

    def rtftobytes(self):
        try:
            with open(self.file_path, 'rb') as file, mmap(file.fileno(), 0, access=ACCESS_READ) as mmapfile:
                return bytes(rtf_to_text(mmapfile.read().decode('utf8'), errors='ignore'), 'utf-8')
        except Exception as err:
            print(f"{get_printabletime()}: RTF error - {self.file_path}: {err}")
            return False

    def xlsxtobytes(self):
        try:
            xls = pandas.ExcelFile(self.file_path)
            text = ""
            for sheet in xls.sheet_names:
                text += pandas.DataFrame.to_string(
                    pandas.read_excel(self.file_path, sheet_name=sheet, engine="openpyxl"))
            return bytes(text, 'utf8')
        except Exception as err:
            print(f"{get_printabletime()}: XLSX error - {self.file_path}: {err}")
            return False

    def getfilepath(self):
        return self.file_path

    def getfilename(self):
        return os.path.basename(self.file_path)
