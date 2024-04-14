# Cryptoscan
This tool recursively scans a specified file or path for files that might contain 
cryptocurrency addresses or seed strings. Additionally, it searches for common wallet file names and paths.

You can also provide Cryptoscan with a single .ufdr or .zip file and it will parse it multiprocessed. 

## Usage:

Cryptoscan.py [-h] [--maxfilesize MAXFILESIZE]
                     [--excludepaths [EXCLUDEPATHS ...]] [--temppath TEMPPATH]
                     [--xlsx]
                     path

- **path**: The path or file to search in.
#### Optional Arguments:
- **-h, --help**: Show this help message and exit.
- **--maxfilesize MAXFILESIZE**: Optional. Maximum file size to scan. E.g., '10B', '10KB', '10MB', '10GB'. Default is '20GB'.
- **--excludepaths [EXCLUDEPATHS ...]**: Optional. A list of directories to exclude from the search.
- **--temppath TEMPPATH**: Optional. Set a specific temporary directory path.
- **--xlsx**: Optional. Convert the CSV output to an Excel file.

## Supported addresses and seed strings:
#### Bitcoin:
* Bitcoin Address
* Bitcoin Address P2SH
* Bitcoin Address Bech32
* Bitcoin Cash Address

#### Other addresses:
* DASH Address
* DOGE Address
* Ethereum Address
* Monero Address
* NEO Address
* Ripple Address

#### Special addresses:
* BIP32 HD wallet private node
* BIP32 HD wallet public node
* BIP38 Encrypted Private Key
* WIF Private key uncompressed public key
* WIF Private key compressed public key

#### Seed strings:
* BIP-39 Seed String
* Monero BIP-39 Seed String

## Supported filetypes:
* Archive files: zip, ufdr, 7z, gz, tar, tgz, rar, rar5
* Document files: docx, pdf, rtf, xlsx
* Web files: html
## TODO:

### Performance
* Check performance on special data. Html seems slow - maybe another module needed?
* Check lock enable and disable as it's a large performance hit with lock.
* Compare performance with old Cryptoscan images, comp & usb


### Validation
* See if match with patterns and long seed strings in all the different supported filetypes. look at the interesting files part to see if it can be lowered


### New features
* Add support for reading forensic images directly. Would need a new module for file handling.
* Make patterns filterable
* Remove some patterns that aren't used often

## Bugs
* N/A


