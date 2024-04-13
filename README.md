# Cryptoscan 2.0
This tool recursively scans a specified file or path for files that might contain 
cryptocurrency addresses or seed strings. Additionally, it searches for common wallet file names and paths. 
    
## Usage: 
Cryptoscan.py [-h] [--maxfilesize MAXFILESIZE]
                     [--excludepaths [EXCLUDEPATHS ...]]
                     path

  -h, --help            show this help message and exit
  
  --maxfilesize MAXFILESIZE
                        Optional: Maximum file size to scan (e.g. 10B, 10KB,
                        10MB, 10GB). Default is 20GB.
                        
  --excludepaths [EXCLUDEPATHS ...]
                        Optional: A list of directories to exclude from the
                        search.


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
* mmap and normal read comparison
* check performance on special data. html seems slow
* test lock enable and disable. large performance hit.
* read_in_chunks: check performance compared to else, all of the different run configs. also check why second chunks memory is larger than first (?)
* compare with old cryptoscan on images, comp & usb


### Validation
* See if match with patterns and long seed strings in all the different supported filetypes. look at the interesting files part to see if it can be lowered


### New features
* work on forensic_read.py. input a 001, e01
* Add improved result for .ufdr files so it's multiprocessed
* Add zip file support, same as for ufdr


## Bugs
* Files above max file size gets rejected even if single file input


