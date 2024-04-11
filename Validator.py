import coinaddrvalidator
import monero
from base58 import b58decode_check
from monero import address
from web3 import Web3


def validate_address(inputaddress, pattern):
    if 'Bitcoin Address' == pattern:
        try:
            return coinaddrvalidator.validate('btc', inputaddress)
        except TypeError:
            return False
        except ValueError:
            return False

    if 'Bitcoin Address P2SH' == pattern:
        try:
            return coinaddrvalidator.validate('btc', inputaddress)
        except TypeError:
            return False
        except ValueError:
            return False

    elif 'Monero Address' == pattern:
        try:
            return monero.address.address(inputaddress)
        except TypeError:
            return False
        except ValueError:
            return False

    elif 'Ethereum Address' == pattern:
        try:
            return Web3.is_address(inputaddress)
        except TypeError:
            return False
        except ValueError:
            return False

    elif 'DOGE Address' == pattern:
        try:
            return coinaddrvalidator.validate('doge', inputaddress)
        except TypeError:
            return False
        except ValueError:
            return False

    elif 'DASH Address' == pattern:
        try:
            return coinaddrvalidator.validate('dash', inputaddress)
        except TypeError:
            return False
        except ValueError:
            return False

    elif 'NEO Address' == pattern:
        try:
            return coinaddrvalidator.validate('neo', inputaddress)
        except TypeError:
            return False
        except ValueError:
            return False

    elif 'Ripple Address' == pattern:
        try:
            return coinaddrvalidator.validate('ripple', inputaddress)
        except TypeError:
            return False
        except ValueError:
            return False

    elif 'Bitcoin Address Bech32' == pattern:
        try:
            return bech32_decode(inputaddress)
        except:
            return False

    elif 'WIF Private key compressed public key' == pattern:
        try:
            return base58check(inputaddress)
        except:
            return False

    elif 'WIF Private key uncompressed public key' == pattern:
        try:
            return base58check(inputaddress)
        except:
            return False

    elif 'BIP32 HD wallet private node' == pattern:
        try:
            return base58check(inputaddress)
        except:
            return False

    elif 'BIP32 HD wallet public node' == pattern:
        try:
            return base58check(inputaddress)
        except:
            return False

    elif 'BIP38 Encrypted Private Key' == pattern:
        try:
            return base58check(inputaddress)
        except:
            return False

    elif 'Bitcoin Cash Address' == pattern:
        try:
            return True
        except:
            return False


def ethereum_check_if_unverifyable(inputaddress):
    if (inputaddress[2:].islower() or inputaddress[2:].isupper()) or (inputaddress[2:].isalpha()) or inputaddress[2:].isnumeric():
        return True


def bech32_decode(bech):
    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    if ((any(ord(x) < 33 or ord(x) > 126 for x in bech)) or
            (bech.lower() != bech and bech.upper() != bech)):
        return False
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return False
    if not all(x in charset for x in bech[pos+1:]):
        return False
    hrp = bech[:pos]
    data = [charset.find(x) for x in bech[pos+1:]]
    if not bech32_verify_checksum(hrp, data):
        return False
    return True


def bech32_polymod(values):
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_verify_checksum(hrp, data):
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1


def base58check(base58address):
    arr = b58decode_check(base58address).hex().lower()
    s = []
    for i in range(0, len(arr) - 1, 2):
        s.append("0x" + arr[i] + arr[i + 1])
    return s


