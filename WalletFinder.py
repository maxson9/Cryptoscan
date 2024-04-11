import re


def filepathconvert(filepath):
    return filepath.replace("\\", "/").lower()


def findwallets(filepath):   # Add wallet files here
    wallet_file_patterns = [
        r'default_wallet$',
        r'seed.seco$',
        r'wallet.dat$',
        r'\w*.wallet$']

    filepathnormalized = filepathconvert(filepath)
    if any(re.search(pattern.lower(), filepathnormalized) for pattern in wallet_file_patterns):
        return filepath


def findwalletpath(filepath):   # Add wallet paths here
    wallet_path_patterns = [
        r'/.armory',
        r'/.bitcoin',
        r'/.bitmonero',
        r'/.electrum',
        r'/bitpay',
        r'/Armory',
        r'/BBQCoin',
        r'/Bither',
        r'/BitCoin',
        r'/Electrum',
        r'/Exodus',
        r'/Franko',
        r'/IOCoin',
        r'/Ixcoin',
        r'/Ledger\sLive',
        r'/Litecoin',
        r'/Mincoin',
        r'/MultiBitHD',
        r'/Multibit-HD',
        r'/YACoin',
        r'/Zcash',
        r'/devcoin',
        r'/mSIGNA_Bitcoin'
    ]

    filepathnormalized = filepathconvert(filepath)
    if any(re.search(pattern.lower(), filepathnormalized) for pattern in wallet_path_patterns):
        return filepath


