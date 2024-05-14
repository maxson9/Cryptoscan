import datetime
import gc
import multiprocessing
import os
import re
import tarfile
import tempfile
import time
import zipfile
from mmap import ACCESS_READ, mmap

import psutil
import py7zr
import rarfile
import regex
from bip_utils import Bip39MnemonicValidator, Bip39Languages, MoneroMnemonicValidator, MoneroLanguages

import Validator
import WalletFinder
from FileHandler import FileHandler

patterns = [
    (re.compile(rb'xprv[a-km-zA-HJ-NP-Z1-9]{107,108}'), 'BIP32 HD wallet private node'),
    (re.compile(rb'xpub[a-km-zA-HJ-NP-Z1-9]{107,108}'), 'BIP32 HD wallet public node'),
    (re.compile(rb'[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}'), 'Monero Address'),
    (re.compile(rb'bc0[ac-hj-np-z02-9]{59}'), 'Bitcoin Address Bech32'),
    (re.compile(rb'6P[a-km-zA-HJ-NP-Z1-9]{56}'), 'BIP38 Encrypted Private Key'),
    (re.compile(rb'[KL][a-km-zA-HJ-NP-Z1-9]{51}'), 'WIF Private key compressed public key'),
    (re.compile(rb'5[a-km-zA-HJ-NP-Z1-9]{50}'), 'WIF Private key uncompressed public key'),
    (re.compile(rb'bitcoincash:\s?[qp]([0-9a-zA-Z]{41})'), 'Bitcoin Cash Address'),
    (re.compile(rb'0x[0-9a-fA-F]{40}'), 'Ethereum Address'),
    (re.compile(rb'bc0[ac-hj-np-z02-9]{39}'), 'Bitcoin Address Bech32'),
    (re.compile(rb'X[1-9A-HJ-NP-Za-km-z]{33}'), 'DASH Address'),
    (re.compile(rb'A[a-km-zA-HJ-NP-Z1-9]{33}'), 'NEO Address'),
    (re.compile(rb'D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}'), 'DOGE Address'),
    (re.compile(rb'r[1-9A-HJ-NP-Za-km-z]{27,35}'), 'Ripple Address'),
    (re.compile(rb'1[a-km-zA-HJ-NP-Z1-9]{25,34}'), 'Bitcoin Address'),
    (re.compile(rb'3[a-km-zA-HJ-NP-Z1-9]{25,34}'), 'Bitcoin Address P2SH'),
    (re.compile(rb'bc1[ac-hj-np-z02-9]{8,87}'), 'Bitcoin Address Bech32'),
    (regex.compile(rb'([a-zA-Z]{3,12}\s){11,23}[a-zA-Z]{3,12}'), 'BIP-39 Seed String')
]
bip39_mnemonicvalidator = Bip39MnemonicValidator(Bip39Languages.ENGLISH)
monero_mnemonicvalidator = MoneroMnemonicValidator(MoneroLanguages.ENGLISH)

wordlist = bip39_mnemonicvalidator.m_mnemonic_decoder.m_words_list.m_idx_to_words
monero_wordlist = monero_mnemonicvalidator.m_mnemonic_decoder.m_words_list.m_idx_to_words


def get_printabletime():
    return datetime.datetime.now().strftime("%H:%M:%S")


def check_lexicographic_order(string):
    words = string.split()
    prev_word = ""
    for word in words:
        if prev_word and prev_word > word:
            return False
        prev_word = word
    return True


def find_bip39_word_sequences(filedata, used_patterns, found_addresses, match_offset):
    matchcount = 0
    last_match_end = 0
    sequence_start = 0
    unique_words = []
    current_wordlist = None

    try:
        for match in re.finditer(b'[A-Za-z]{3,8}', filedata):
            matchtext = match.group().decode('utf8').lower()

            if current_wordlist is None:
                if matchtext in wordlist:
                    current_wordlist = wordlist
                elif matchtext in monero_wordlist:
                    current_wordlist = monero_wordlist

            if current_wordlist and matchtext in current_wordlist:
                current_start = match.start()
                if matchtext not in unique_words:
                    if (current_start - last_match_end) < 15 or matchcount == 0:
                        if matchcount == 0:
                            sequence_start = current_start

                        matchcount += 1
                        unique_words.append(matchtext)
                        if matchcount == 12:
                            used_patterns.append('BIP-39 Seed String - Interesting file')
                            found_addresses.append(' '.join(unique_words))
                            match_offset.append(sequence_start)
                        last_match_end = match.end()
                    else:
                        matchcount = 0
                        unique_words.clear()
                        current_wordlist = None

    except UnicodeDecodeError as err:
        print(f"{get_printabletime()}: Unicode decode error in longseed processing: {err}")
    except Exception as err:
        print(f"{get_printabletime()}: Unexpected error in longseed processing: {err}")


def file_data_search(filedata, filepath, printablesize):
    found_addresses = []
    found_seedstrings_count = 0
    start_time = time.time()
    last_check_time = start_time

    used_offsets = set()
    used_patterns = []
    match_offset = []

    for pattern, description in patterns:
        current_time = time.time()
        if current_time - last_check_time > 15:
            last_check_time = current_time
            print(f"{get_printabletime()}: Still processing {filepath} ({printablesize}). Currently searching for: {description}.")

        if description == 'BIP-39 Seed String':
            for match in regex.finditer(pattern, filedata, overlapped=True):
                start, end = match.start(), match.end()
                words = match.group().decode('utf8').lower().split()

                if any(start in offset_window for offset_window in used_offsets):    # Check if already have match in this offset window
                    continue

                '''
                Seed generators
                https://iancoleman.io/bip39/ bip39
                https://xmr.llcoins.net/ monero
                
                TODO: rewrite interesting file
                      add support for monero in function below
                '''

                if len(set(words)) >= 12 and (all(word in wordlist for word in words) or all(word in monero_wordlist for word in words)):
                    for length in [24, 12]:
                        for i in range(len(words) - length + 1):
                            current_seed_string = ' '.join(words[i:i + length]).lower()
                            if bip39_mnemonicvalidator.IsValid(current_seed_string):
                                if not check_lexicographic_order(current_seed_string):
                                    used_patterns.append('BIP-39 Seed String')
                                    found_addresses.append(current_seed_string)
                                    match_offset.append(start)
                                    found_seedstrings_count += 1
                                    used_offsets.add(range(start, start + len(current_seed_string)))
                                    break
                        else:
                            continue
                        break

        else:
            for match in pattern.finditer(filedata):
                start, end = match.start(), match.end()
                matched_string = filedata[start:end].decode("utf-8")
                if Validator.validate_address(matched_string, description):
                    if any(start in range(offset.start, offset.stop) for offset in used_offsets):
                        continue

                    if description == 'Ethereum Address' and Validator.ethereum_check_if_unverifyable(matched_string):
                        used_patterns.append('Ethereum Address (unverifyable)')
                    else:
                        used_patterns.append(description)
                    found_addresses.append(matched_string)
                    match_offset.append(start)
                    used_offsets.add(range(start, end))

    if found_seedstrings_count == 0:
        find_bip39_word_sequences(filedata, used_patterns, found_addresses, match_offset)

    return used_patterns, found_addresses, match_offset


def read_in_chunks(file_instance, overlap_size=1024):
    chunk_size = int((psutil.virtual_memory().available / int(multiprocessing.cpu_count() - 2)) * 0.90)
    total_size = file_instance.getfilesize()
    total_chunks = (total_size // chunk_size) + (1 if total_size % chunk_size > 0 else 0)
    current_chunk = 1

    with open(file_instance.getfilepath(), 'rb') as file:
        prev_chunk_end = b''
        while True:
            chunk = file.read(chunk_size)
            if not chunk:
                break
            combined_chunk = prev_chunk_end + chunk
            yield combined_chunk, current_chunk, total_chunks
            prev_chunk_end = chunk[-overlap_size:]
            current_chunk += 1


def process_file(inputmaxsize, excluded_paths, archive_path, temppath, file_path):
    file_instance = FileHandler(file_path)
    filesize = file_instance.getfilesize()

    if file_instance.check_if_excluded(excluded_paths):
        return False

    if archive_path:
        file_path = archive_path

    print(f"{get_printabletime()}: Scanning: {file_path} ({file_instance.getfilesize_printable()})")
    found_wallet_file = WalletFinder.findwallets(file_path)
    found_wallet_path = WalletFinder.findwalletpath(file_path)

    if file_instance.filecheck(inputmaxsize):
        return False

    try:
        results = []
        supported_archives = ['.zip', '.7z', '.tar', '.gz', '.tgz', '.rar']

        if file_instance.getfileextension() in supported_archives:
            print(f"{get_printabletime()}: Extracting files from: {file_path}")
            results = process_archive_file(inputmaxsize, excluded_paths, temppath, file_path)
        else:
            file_data = file_instance.getspecialfiledata()

            if file_data:
                results = file_data_search(file_data, file_path, file_instance.getfilesize_printable())

            elif file_instance.getfilesize() > 1024 * 1024 * 1024:
                combined_results = [[], [], []]
                for file_data, chunk_num, total_chunks in read_in_chunks(file_instance):
                    chunk_size = len(file_data)
                    for unit in ['B', 'KB', 'MB', 'GB']:
                        if chunk_size < 1024.0:
                            break
                        chunk_size /= 1024.0
                    print(f"{get_printabletime()}: Processing {file_path}: Chunk {chunk_num} of {total_chunks}, approximately {chunk_size:.{0}f}{unit}.")
                    chunk_results = file_data_search(file_data, file_path, file_instance.getfilesize_printable())
                    combined_results = [combined + chunk for combined, chunk in zip(combined_results, chunk_results)]
                results = combined_results

            else:
                with open(file_instance.getfilepath(), 'rb') as file, mmap(file.fileno(), 0, access=ACCESS_READ) as mmapfile:
                    results = file_data_search(mmapfile.read(), file_path, file_instance.getfilesize_printable())

        if found_wallet_file:
            results[0].append("Wallet File")
            results[1].append("N/A")
            results[2].append(0)

        if found_wallet_path:
            results[0].append("Wallet Path")
            results[1].append("N/A")
            results[2].append(0)

        gc.collect()

        print(f"{get_printabletime()}: Done with: {file_path} ({file_instance.getfilesize_printable()})")

        if archive_path or file_instance.getfileextension() in supported_archives:
            return results, archive_path, filesize
        else:
            return results, file_path, filesize

    except Exception as err:
        print(f"{get_printabletime()}: An error occurred while processing the file: {err}")
        return False


def extract_archive(archive_file_path, extract_to):
    extension = os.path.splitext(archive_file_path)[1].lower()
    try:
        if extension == '.zip':
            with zipfile.ZipFile(archive_file_path, 'r') as archive_ref:
                archive_ref.extractall(extract_to)
        elif extension == '.7z':
            with py7zr.SevenZipFile(archive_file_path, 'r') as archive_ref:
                archive_ref.extractall(extract_to)
        elif extension in ['.tar', '.gz', '.tgz']:
            with tarfile.open(archive_file_path, 'r:*') as archive_ref:
                archive_ref.extractall(extract_to)
        elif extension in ['.rar', '.rar5']:
            with rarfile.RarFile(archive_file_path, 'r') as archive_ref:
                archive_ref.extractall(extract_to)
    except Exception as err:
        print(f"{get_printabletime()}: Error extracting archive {archive_file_path}: {err}")


def process_archive_file(inputmaxsize, excluded_paths, temppath_, archive_file_path):
    results = []
    try:
        if temppath_:
            temp_dir = tempfile.TemporaryDirectory(dir=temppath_)
        else:
            temp_dir = tempfile.TemporaryDirectory()
        with temp_dir as temp_dir:
            extract_archive(archive_file_path, temp_dir)

            while True:
                archives_extracted = False
                for root, dirs, files in os.walk(temp_dir):
                    for file_name in files:
                        full_path = os.path.join(root, file_name)
                        if os.path.splitext(full_path)[1].lower() in ['.zip', '.7z', '.gz', '.tar', '.tgz', '.rar',
                                                                      '.rar5']:

                            extract_archive(full_path, full_path + "_")
                            os.remove(full_path)  # Remove the archive after extraction
                            archives_extracted = True

                if not archives_extracted:
                    break

            for root, dirs, files in os.walk(temp_dir):
                for file_name in files:
                    full_path = os.path.join(root, file_name)
                    if os.path.isdir(full_path):
                        continue

                    relative_path = os.path.relpath(full_path, temp_dir)
                    archive_file_path_printable = os.path.join(archive_file_path, relative_path)

                    file_results = process_file(inputmaxsize, excluded_paths, archive_file_path_printable, temppath_, full_path)
                    if file_results:
                        results.append(file_results)

        return results

    except Exception as err:
        print(f"{get_printabletime()}: Error reading archive: {err}")
