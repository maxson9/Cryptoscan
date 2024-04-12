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

import Validator
import WalletFinder
from FileHandler import FileHandler

patterns = [
    (re.compile(rb'xprv[a-km-zA-HJ-NP-Z1-9]{107,108}'), 'BIP32 HD wallet private node'),
    (re.compile(rb'x\x00p\x00r\x00v\x00([a-km-zA-HJ-NP-Z1-9]\x00){107,108}'), 'BIP32 HD wallet private node'),  # (escape characters)
    (re.compile(rb'xpub[a-km-zA-HJ-NP-Z1-9]{107,108}'), 'BIP32 HD wallet public node'),
    (re.compile(rb'x\x00p\x00u\x00b\x00([a-km-zA-HJ-NP-Z1-9]\x00){107,108}'), 'BIP32 HD wallet public node'),  # (escape characters)
    (re.compile(rb'4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}'), 'Monero Address'),
    (re.compile(rb'bc0[ac-hj-np-z02-9]{59}'), 'Bitcoin Address Bech32'),
    (re.compile(rb'6P[a-km-zA-HJ-NP-Z1-9]{56}'), 'BIP38 Encrypted Private Key'),
    (re.compile(rb'6\x00P\x00([a-km-zA-HJ-NP-Z1-9]\x00){56}'), 'BIP38 Encrypted Private Key'),  # (escape characters)
    (re.compile(rb'[KL][a-km-zA-HJ-NP-Z1-9]{51}'), 'WIF Private key compressed public key'),
    (re.compile(rb'[KL]\x00([a-km-zA-HJ-NP-Z1-9]\x00){51}'), 'WIF Private key compressed public key'),  # (escape characters)
    (re.compile(rb'5[a-km-zA-HJ-NP-Z1-9]{50}'), 'WIF Private key uncompressed public key'),
    (re.compile(rb'5\x00([a-km-zA-HJ-NP-Z1-9]\x00){50}'), 'WIF Private key uncompressed public key'),  # (escape characters)
    (re.compile(rb'bitcoincash:\s?[qp]([0-9a-zA-Z]{41})'), 'Bitcoin Cash Address'),
    (re.compile(rb'0x[0-9a-fA-F]{40}'), 'Ethereum Address'),
    (re.compile(rb'bc0[ac-hj-np-z02-9]{39}'), 'Bitcoin Address Bech32'),
    (re.compile(rb'X[1-9A-HJ-NP-Za-km-z]{33}'), 'DASH Address'),
    (re.compile(rb'A[a-km-zA-HJ-NP-Z1-9]{33}'), 'NEO Address'),
    (re.compile(rb'D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}'), 'DOGE Address'),
    (re.compile(rb'r[1-9A-HJ-NP-Za-km-z]{27,35}'), 'Ripple Address'),
    (re.compile(rb'1[a-km-zA-HJ-NP-Z1-9]{25,34}'), 'Bitcoin Address'),
    (re.compile(rb'1\x00([a-km-zA-HJ-NP-Z1-9]\x00){25,34}'), 'Bitcoin Address'),  # (escape characters)
    (re.compile(rb'3[a-km-zA-HJ-NP-Z1-9]{25,34}'), 'Bitcoin Address P2SH'),
    (re.compile(rb'3\x00([a-km-zA-HJ-NP-Z1-9]\x00){25,34}'), 'Bitcoin Address P2SH'),  # (escape characters)
    (re.compile(rb'bc1[ac-hj-np-z02-9]{8,87}'), 'Bitcoin Address Bech32'),
    (re.compile(rb'([a-zA-Z]{3,12}\s){11}[a-zA-Z]{3,12}'), 'BIP-39 Seed String')
]

wordlist = {'abandon','ability','able','about','above','absent','absorb','abstract','absurd','abuse','access','accident',
               'account','accuse','achieve','acid','acoustic','acquire','across','act','action','actor','actress','actual',
               'adapt','add','addict','address','adjust','admit','adult','advance','advice','aerobic','affair','afford',
               'afraid','again','age','agent','agree','ahead','aim','air','airport','aisle','alarm','album','alcohol',
               'alert', 'alien', 'all', 'alley', 'allow', 'almost', 'alone', 'alpha', 'already', 'also', 'alter', 'always',
               'amateur', 'amazing', 'among', 'amount', 'amused', 'analyst', 'anchor', 'ancient', 'anger', 'angle', 'angry',
               'animal', 'ankle', 'announce', 'annual', 'another', 'answer', 'antenna', 'antique', 'anxiety', 'any',
               'apart', 'apology', 'appear', 'apple', 'approve', 'april', 'arch', 'arctic', 'area', 'arena', 'argue', 'arm',
               'armed', 'armor', 'army', 'around', 'arrange', 'arrest', 'arrive', 'arrow', 'art', 'artefact', 'artist',
               'artwork', 'ask', 'aspect', 'assault', 'asset', 'assist', 'assume', 'asthma', 'athlete', 'atom', 'attack',
               'attend', 'attitude', 'attract', 'auction', 'audit', 'august', 'aunt', 'author', 'auto', 'autumn', 'average',
               'avocado', 'avoid', 'awake', 'aware', 'away', 'awesome', 'awful', 'awkward', 'axis', 'baby', 'bachelor',
               'bacon', 'badge', 'bag', 'balance', 'balcony', 'ball', 'bamboo', 'banana', 'banner', 'bar', 'barely',
               'bargain', 'barrel', 'base', 'basic', 'basket', 'battle', 'beach', 'bean', 'beauty', 'because', 'become',
               'beef', 'before', 'begin', 'behave', 'behind', 'believe', 'below', 'belt', 'bench', 'benefit', 'best',
               'betray', 'better', 'between', 'beyond', 'bicycle', 'bid', 'bike', 'bind', 'biology', 'bird', 'birth',
               'bitter', 'black', 'blade', 'blame', 'blanket', 'blast', 'bleak', 'bless', 'blind', 'blood', 'blossom',
               'blouse', 'blue', 'blur', 'blush', 'board', 'boat', 'body', 'boil', 'bomb', 'bone', 'bonus', 'book', 'boost',
               'border', 'boring', 'borrow', 'boss', 'bottom', 'bounce', 'box', 'boy', 'bracket', 'brain', 'brand', 'brass',
               'brave', 'bread', 'breeze', 'brick', 'bridge', 'brief', 'bright', 'bring', 'brisk', 'broccoli', 'broken',
               'bronze', 'broom', 'brother', 'brown', 'brush', 'bubble', 'buddy', 'budget', 'buffalo', 'build', 'bulb',
               'bulk', 'bullet', 'bundle', 'bunker', 'burden', 'burger', 'burst', 'bus', 'business', 'busy', 'butter',
               'buyer', 'buzz', 'cabbage', 'cabin', 'cable', 'cactus', 'cage', 'cake', 'call', 'calm', 'camera', 'camp',
               'can', 'canal', 'cancel', 'candy', 'cannon', 'canoe', 'canvas', 'canyon', 'capable', 'capital', 'captain',
               'car', 'carbon', 'card', 'cargo', 'carpet', 'carry', 'cart', 'case', 'cash', 'casino', 'castle', 'casual',
               'cat', 'catalog', 'catch', 'category', 'cattle', 'caught', 'cause', 'caution', 'cave', 'ceiling', 'celery',
               'cement', 'census', 'century', 'cereal', 'certain', 'chair', 'chalk', 'champion', 'change', 'chaos',
               'chapter', 'charge', 'chase', 'chat', 'cheap', 'check', 'cheese', 'chef', 'cherry', 'chest', 'chicken',
               'chief', 'child', 'chimney', 'choice', 'choose', 'chronic', 'chuckle', 'chunk', 'churn', 'cigar', 'cinnamon',
               'circle', 'citizen', 'city', 'civil', 'claim', 'clap', 'clarify', 'claw', 'clay', 'clean', 'clerk', 'clever',
               'click', 'client', 'cliff', 'climb', 'clinic', 'clip', 'clock', 'clog', 'close', 'cloth', 'cloud', 'clown',
               'club', 'clump', 'cluster', 'clutch', 'coach', 'coast', 'coconut', 'code', 'coffee', 'coil', 'coin',
               'collect', 'color', 'column', 'combine', 'come', 'comfort', 'comic', 'common', 'company', 'concert',
               'conduct', 'confirm', 'congress', 'connect', 'consider', 'control', 'convince', 'cook', 'cool', 'copper',
               'copy', 'coral', 'core', 'corn', 'correct', 'cost', 'cotton', 'couch', 'country', 'couple', 'course',
               'cousin', 'cover', 'coyote', 'crack', 'cradle', 'craft', 'cram', 'crane', 'crash', 'crater', 'crawl',
               'crazy', 'cream', 'credit', 'creek', 'crew', 'cricket', 'crime', 'crisp', 'critic', 'crop', 'cross',
               'crouch', 'crowd', 'crucial', 'cruel', 'cruise', 'crumble', 'crunch', 'crush', 'cry', 'crystal', 'cube',
               'culture', 'cup', 'cupboard', 'curious', 'current', 'curtain', 'curve', 'cushion', 'custom', 'cute', 'cycle',
               'dad', 'damage', 'damp', 'dance', 'danger', 'daring', 'dash', 'daughter', 'dawn', 'day', 'deal', 'debate',
               'debris', 'decade', 'december', 'decide', 'decline', 'decorate', 'decrease', 'deer', 'defense', 'define',
               'defy', 'degree', 'delay', 'deliver', 'demand', 'demise', 'denial', 'dentist', 'deny', 'depart', 'depend',
               'deposit', 'depth', 'deputy', 'derive', 'describe', 'desert', 'design', 'desk', 'despair', 'destroy',
               'detail', 'detect', 'develop', 'device', 'devote', 'diagram', 'dial', 'diamond', 'diary', 'dice', 'diesel',
               'diet', 'differ', 'digital', 'dignity', 'dilemma', 'dinner', 'dinosaur', 'direct', 'dirt', 'disagree',
               'discover', 'disease', 'dish', 'dismiss', 'disorder', 'display', 'distance', 'divert', 'divide', 'divorce',
               'dizzy', 'doctor', 'document', 'dog', 'doll', 'dolphin', 'domain', 'donate', 'donkey', 'donor', 'door',
               'dose', 'double', 'dove', 'draft', 'dragon', 'drama', 'drastic', 'draw', 'dream', 'dress', 'drift', 'drill',
               'drink', 'drip', 'drive', 'drop', 'drum', 'dry', 'duck', 'dumb', 'dune', 'during', 'dust', 'dutch', 'duty',
               'dwarf', 'dynamic', 'eager', 'eagle', 'early', 'earn', 'earth', 'easily', 'east', 'easy', 'echo', 'ecology',
               'economy', 'edge', 'edit', 'educate', 'effort', 'egg', 'eight', 'either', 'elbow', 'elder', 'electric',
               'elegant', 'element', 'elephant', 'elevator', 'elite', 'else', 'embark', 'embody', 'embrace', 'emerge',
               'emotion', 'employ', 'empower', 'empty', 'enable', 'enact', 'end', 'endless', 'endorse', 'enemy', 'energy',
               'enforce', 'engage', 'engine', 'enhance', 'enjoy', 'enlist', 'enough', 'enrich', 'enroll', 'ensure', 'enter',
               'entire', 'entry', 'envelope', 'episode', 'equal', 'equip', 'era', 'erase', 'erode', 'erosion', 'error',
               'erupt', 'escape', 'essay', 'essence', 'estate', 'eternal', 'ethics', 'evidence', 'evil', 'evoke', 'evolve',
               'exact', 'example', 'excess', 'exchange', 'excite', 'exclude', 'excuse', 'execute', 'exercise', 'exhaust',
               'exhibit', 'exile', 'exist', 'exit', 'exotic', 'expand', 'expect', 'expire', 'explain', 'expose', 'express',
               'extend', 'extra', 'eye', 'eyebrow', 'fabric', 'face', 'faculty', 'fade', 'faint', 'faith', 'fall', 'false',
               'fame', 'family', 'famous', 'fan', 'fancy', 'fantasy', 'farm', 'fashion', 'fat', 'fatal', 'father',
               'fatigue', 'fault', 'favorite', 'feature', 'february', 'federal', 'fee', 'feed', 'feel', 'female', 'fence',
               'festival', 'fetch', 'fever', 'few', 'fiber', 'fiction', 'field', 'figure', 'file', 'film', 'filter',
               'final', 'find', 'fine', 'finger', 'finish', 'fire', 'firm', 'first', 'fiscal', 'fish', 'fit', 'fitness',
               'fix', 'flag', 'flame', 'flash', 'flat', 'flavor', 'flee', 'flight', 'flip', 'float', 'flock', 'floor',
               'flower', 'fluid', 'flush', 'fly', 'foam', 'focus', 'fog', 'foil', 'fold', 'follow', 'food', 'foot', 'force',
               'forest', 'forget', 'fork', 'fortune', 'forum', 'forward', 'fossil', 'foster', 'found', 'fox', 'fragile',
               'frame', 'frequent', 'fresh', 'friend', 'fringe', 'frog', 'front', 'frost', 'frown', 'frozen', 'fruit',
               'fuel', 'fun', 'funny', 'furnace', 'fury', 'future', 'gadget', 'gain', 'galaxy', 'gallery', 'game', 'gap',
               'garage', 'garbage', 'garden', 'garlic', 'garment', 'gas', 'gasp', 'gate', 'gather', 'gauge', 'gaze',
               'general', 'genius', 'genre', 'gentle', 'genuine', 'gesture', 'ghost', 'giant', 'gift', 'giggle', 'ginger',
               'giraffe', 'girl', 'give', 'glad', 'glance', 'glare', 'glass', 'glide', 'glimpse', 'globe', 'gloom', 'glory',
               'glove', 'glow', 'glue', 'goat', 'goddess', 'gold', 'good', 'goose', 'gorilla', 'gospel', 'gossip', 'govern',
               'gown', 'grab', 'grace', 'grain', 'grant', 'grape', 'grass', 'gravity', 'great', 'green', 'grid', 'grief',
               'grit', 'grocery', 'group', 'grow', 'grunt', 'guard', 'guess', 'guide', 'guilt', 'guitar', 'gun', 'gym',
               'habit', 'hair', 'half', 'hammer', 'hamster', 'hand', 'happy', 'harbor', 'hard', 'harsh', 'harvest', 'hat',
               'have', 'hawk', 'hazard', 'head', 'health', 'heart', 'heavy', 'hedgehog', 'height', 'hello', 'helmet',
               'help', 'hen', 'hero', 'hidden', 'high', 'hill', 'hint', 'hip', 'hire', 'history', 'hobby', 'hockey', 'hold',
               'hole', 'holiday', 'hollow', 'home', 'honey', 'hood', 'hope', 'horn', 'horror', 'horse', 'hospital', 'host',
               'hotel', 'hour', 'hover', 'hub', 'huge', 'human', 'humble', 'humor', 'hundred', 'hungry', 'hunt', 'hurdle',
               'hurry', 'hurt', 'husband', 'hybrid', 'ice', 'icon', 'idea', 'identify', 'idle', 'ignore', 'ill', 'illegal',
               'illness', 'image', 'imitate', 'immense', 'immune', 'impact', 'impose', 'improve', 'impulse', 'inch',
               'include', 'income', 'increase', 'index', 'indicate', 'indoor', 'industry', 'infant', 'inflict', 'inform',
               'inhale', 'inherit', 'initial', 'inject', 'injury', 'inmate', 'inner', 'innocent', 'input', 'inquiry',
               'insane', 'insect', 'inside', 'inspire', 'install', 'intact', 'interest', 'into', 'invest', 'invite',
               'involve', 'iron', 'island', 'isolate', 'issue', 'item', 'ivory', 'jacket', 'jaguar', 'jar', 'jazz',
               'jealous', 'jeans', 'jelly', 'jewel', 'job', 'join', 'joke', 'journey', 'joy', 'judge', 'juice', 'jump',
               'jungle', 'junior', 'junk', 'just', 'kangaroo', 'keen', 'keep', 'ketchup', 'key', 'kick', 'kid', 'kidney',
               'kind', 'kingdom', 'kiss', 'kit', 'kitchen', 'kite', 'kitten', 'kiwi', 'knee', 'knife', 'knock', 'know',
               'lab', 'label', 'labor', 'ladder', 'lady', 'lake', 'lamp', 'language', 'laptop', 'large', 'later', 'latin',
               'laugh', 'laundry', 'lava', 'law', 'lawn', 'lawsuit', 'layer', 'lazy', 'leader', 'leaf', 'learn', 'leave',
               'lecture', 'left', 'leg', 'legal', 'legend', 'leisure', 'lemon', 'lend', 'length', 'lens', 'leopard',
               'lesson', 'letter', 'level', 'liar', 'liberty', 'library', 'license', 'life', 'lift', 'light', 'like',
               'limb', 'limit', 'link', 'lion', 'liquid', 'list', 'little', 'live', 'lizard', 'load', 'loan', 'lobster',
               'local', 'lock', 'logic', 'lonely', 'long', 'loop', 'lottery', 'loud', 'lounge', 'love', 'loyal', 'lucky',
               'luggage', 'lumber', 'lunar', 'lunch', 'luxury', 'lyrics', 'machine', 'mad', 'magic', 'magnet', 'maid',
               'mail', 'main', 'major', 'make', 'mammal', 'man', 'manage', 'mandate', 'mango', 'mansion', 'manual', 'maple',
               'marble', 'march', 'margin', 'marine', 'market', 'marriage', 'mask', 'mass', 'master', 'match', 'material',
               'math', 'matrix', 'matter', 'maximum', 'maze', 'meadow', 'mean', 'measure', 'meat', 'mechanic', 'medal',
               'media', 'melody', 'melt', 'member', 'memory', 'mention', 'menu', 'mercy', 'merge', 'merit', 'merry', 'mesh',
               'message', 'metal', 'method', 'middle', 'midnight', 'milk', 'million', 'mimic', 'mind', 'minimum', 'minor',
               'minute', 'miracle', 'mirror', 'misery', 'miss', 'mistake', 'mix', 'mixed', 'mixture', 'mobile', 'model',
               'modify', 'mom', 'moment', 'monitor', 'monkey', 'monster', 'month', 'moon', 'moral', 'more', 'morning',
               'mosquito', 'mother', 'motion', 'motor', 'mountain', 'mouse', 'move', 'movie', 'much', 'muffin', 'mule',
               'multiply', 'muscle', 'museum', 'mushroom', 'music', 'must', 'mutual', 'myself', 'mystery', 'myth', 'naive',
               'name', 'napkin', 'narrow', 'nasty', 'nation', 'nature', 'near', 'neck', 'need', 'negative', 'neglect',
               'neither', 'nephew', 'nerve', 'nest', 'net', 'network', 'neutral', 'never', 'news', 'next', 'nice', 'night',
               'noble', 'noise', 'nominee', 'noodle', 'normal', 'north', 'nose', 'notable', 'note', 'nothing', 'notice',
               'novel', 'now', 'nuclear', 'number', 'nurse', 'nut', 'oak', 'obey', 'object', 'oblige', 'obscure', 'observe',
               'obtain', 'obvious', 'occur', 'ocean', 'october', 'odor', 'off', 'offer', 'office', 'often', 'oil', 'okay',
               'old', 'olive', 'olympic', 'omit', 'once', 'one', 'onion', 'online', 'only', 'open', 'opera', 'opinion',
               'oppose', 'option', 'orange', 'orbit', 'orchard', 'order', 'ordinary', 'organ', 'orient', 'original',
               'orphan', 'ostrich', 'other', 'outdoor', 'outer', 'output', 'outside', 'oval', 'oven', 'over', 'own',
               'owner', 'oxygen', 'oyster', 'ozone', 'pact', 'paddle', 'page', 'pair', 'palace', 'palm', 'panda', 'panel',
               'panic', 'panther', 'paper', 'parade', 'parent', 'park', 'parrot', 'party', 'pass', 'patch', 'path',
               'patient', 'patrol', 'pattern', 'pause', 'pave', 'payment', 'peace', 'peanut', 'pear', 'peasant', 'pelican',
               'pen', 'penalty', 'pencil', 'people', 'pepper', 'perfect', 'permit', 'person', 'pet', 'phone', 'photo',
               'phrase', 'physical', 'piano', 'picnic', 'picture', 'piece', 'pig', 'pigeon', 'pill', 'pilot', 'pink',
               'pioneer', 'pipe', 'pistol', 'pitch', 'pizza', 'place', 'planet', 'plastic', 'plate', 'play', 'please',
               'pledge', 'pluck', 'plug', 'plunge', 'poem', 'poet', 'point', 'polar', 'pole', 'police', 'pond', 'pony',
               'pool', 'popular', 'portion', 'position', 'possible', 'post', 'potato', 'pottery', 'poverty', 'powder',
               'power', 'practice', 'praise', 'predict', 'prefer', 'prepare', 'present', 'pretty', 'prevent', 'price',
               'pride', 'primary', 'print', 'priority', 'prison', 'private', 'prize', 'problem', 'process', 'produce',
               'profit', 'program', 'project', 'promote', 'proof', 'property', 'prosper', 'protect', 'proud', 'provide',
               'public', 'pudding', 'pull', 'pulp', 'pulse', 'pumpkin', 'punch', 'pupil', 'puppy', 'purchase', 'purity',
               'purpose', 'purse', 'push', 'put', 'puzzle', 'pyramid', 'quality', 'quantum', 'quarter', 'question', 'quick',
               'quit', 'quiz', 'quote', 'rabbit', 'raccoon', 'race', 'rack', 'radar', 'radio', 'rail', 'rain', 'raise',
               'rally', 'ramp', 'ranch', 'random', 'range', 'rapid', 'rare', 'rate', 'rather', 'raven', 'raw', 'razor',
               'ready', 'real', 'reason', 'rebel', 'rebuild', 'recall', 'receive', 'recipe', 'record', 'recycle', 'reduce',
               'reflect', 'reform', 'refuse', 'region', 'regret', 'regular', 'reject', 'relax', 'release', 'relief', 'rely',
               'remain', 'remember', 'remind', 'remove', 'render', 'renew', 'rent', 'reopen', 'repair', 'repeat', 'replace',
               'report', 'require', 'rescue', 'resemble', 'resist', 'resource', 'response', 'result', 'retire', 'retreat',
               'return', 'reunion', 'reveal', 'review', 'reward', 'rhythm', 'rib', 'ribbon', 'rice', 'rich', 'ride',
               'ridge', 'rifle', 'right', 'rigid', 'ring', 'riot', 'ripple', 'risk', 'ritual', 'rival', 'river', 'road',
               'roast', 'robot', 'robust', 'rocket', 'romance', 'roof', 'rookie', 'room', 'rose', 'rotate', 'rough',
               'round', 'route', 'royal', 'rubber', 'rude', 'rug', 'rule', 'run', 'runway', 'rural', 'sad', 'saddle',
               'sadness', 'safe', 'sail', 'salad', 'salmon', 'salon', 'salt', 'salute', 'same', 'sample', 'sand', 'satisfy',
               'satoshi', 'sauce', 'sausage', 'save', 'say', 'scale', 'scan', 'scare', 'scatter', 'scene', 'scheme',
               'school', 'science', 'scissors', 'scorpion', 'scout', 'scrap', 'screen', 'script', 'scrub', 'sea', 'search',
               'season', 'seat', 'second', 'secret', 'section', 'security', 'seed', 'seek', 'segment', 'select', 'sell',
               'seminar', 'senior', 'sense', 'sentence', 'series', 'service', 'session', 'settle', 'setup', 'seven',
               'shadow', 'shaft', 'shallow', 'share', 'shed', 'shell', 'sheriff', 'shield', 'shift', 'shine', 'ship',
               'shiver', 'shock', 'shoe', 'shoot', 'shop', 'short', 'shoulder', 'shove', 'shrimp', 'shrug', 'shuffle',
               'shy', 'sibling', 'sick', 'side', 'siege', 'sight', 'sign', 'silent', 'silk', 'silly', 'silver', 'similar',
               'simple', 'since', 'sing', 'siren', 'sister', 'situate', 'six', 'size', 'skate', 'sketch', 'ski', 'skill',
               'skin', 'skirt', 'skull', 'slab', 'slam', 'sleep', 'slender', 'slice', 'slide', 'slight', 'slim', 'slogan',
               'slot', 'slow', 'slush', 'small', 'smart', 'smile', 'smoke', 'smooth', 'snack', 'snake', 'snap', 'sniff',
               'snow', 'soap', 'soccer', 'social', 'sock', 'soda', 'soft', 'solar', 'soldier', 'solid', 'solution', 'solve',
               'someone', 'song', 'soon', 'sorry', 'sort', 'soul', 'sound', 'soup', 'source', 'south', 'space', 'spare',
               'spatial', 'spawn', 'speak', 'special', 'speed', 'spell', 'spend', 'sphere', 'spice', 'spider', 'spike',
               'spin', 'spirit', 'split', 'spoil', 'sponsor', 'spoon', 'sport', 'spot', 'spray', 'spread', 'spring', 'spy',
               'square', 'squeeze', 'squirrel', 'stable', 'stadium', 'staff', 'stage', 'stairs', 'stamp', 'stand', 'start',
               'state', 'stay', 'steak', 'steel', 'stem', 'step', 'stereo', 'stick', 'still', 'sting', 'stock', 'stomach',
               'stone', 'stool', 'story', 'stove', 'strategy', 'street', 'strike', 'strong', 'struggle', 'student', 'stuff',
               'stumble', 'style', 'subject', 'submit', 'subway', 'success', 'such', 'sudden', 'suffer', 'sugar', 'suggest',
               'suit', 'summer', 'sun', 'sunny', 'sunset', 'super', 'supply', 'supreme', 'sure', 'surface', 'surge',
               'surprise', 'surround', 'survey', 'suspect', 'sustain', 'swallow', 'swamp', 'swap', 'swarm', 'swear',
               'sweet', 'swift', 'swim', 'swing', 'switch', 'sword', 'symbol', 'symptom', 'syrup', 'system', 'table',
               'tackle', 'tag', 'tail', 'talent', 'talk', 'tank', 'tape', 'target', 'task', 'taste', 'tattoo', 'taxi',
               'teach', 'team', 'tell', 'ten', 'tenant', 'tennis', 'tent', 'term', 'test', 'text', 'thank', 'that', 'theme',
               'then', 'theory', 'there', 'they', 'thing', 'this', 'thought', 'three', 'thrive', 'throw', 'thumb',
               'thunder', 'ticket', 'tide', 'tiger', 'tilt', 'timber', 'time', 'tiny', 'tip', 'tired', 'tissue', 'title',
               'toast', 'tobacco', 'today', 'toddler', 'toe', 'together', 'toilet', 'token', 'tomato', 'tomorrow', 'tone',
               'tongue', 'tonight', 'tool', 'tooth', 'top', 'topic', 'topple', 'torch', 'tornado', 'tortoise', 'toss',
               'total', 'tourist', 'toward', 'tower', 'town', 'toy', 'track', 'trade', 'traffic', 'tragic', 'train',
               'transfer', 'trap', 'trash', 'travel', 'tray', 'treat', 'tree', 'trend', 'trial', 'tribe', 'trick',
               'trigger', 'trim', 'trip', 'trophy', 'trouble', 'truck', 'true', 'truly', 'trumpet', 'trust', 'truth', 'try',
               'tube', 'tuition', 'tumble', 'tuna', 'tunnel', 'turkey', 'turn', 'turtle', 'twelve', 'twenty', 'twice',
               'twin', 'twist', 'two', 'type', 'typical', 'ugly', 'umbrella', 'unable', 'unaware', 'uncle', 'uncover',
               'under', 'undo', 'unfair', 'unfold', 'unhappy', 'uniform', 'unique', 'unit', 'universe', 'unknown', 'unlock',
               'until', 'unusual', 'unveil', 'update', 'upgrade', 'uphold', 'upon', 'upper', 'upset', 'urban', 'urge',
               'usage', 'use', 'used', 'useful', 'useless', 'usual', 'utility', 'vacant', 'vacuum', 'vague', 'valid',
               'valley', 'valve', 'van', 'vanish', 'vapor', 'various', 'vast', 'vault', 'vehicle', 'velvet', 'vendor',
               'venture', 'venue', 'verb', 'verify', 'version', 'very', 'vessel', 'veteran', 'viable', 'vibrant', 'vicious',
               'victory', 'video', 'view', 'village', 'vintage', 'violin', 'virtual', 'virus', 'visa', 'visit', 'visual',
               'vital', 'vivid', 'vocal', 'voice', 'void', 'volcano', 'volume', 'vote', 'voyage', 'wage', 'wagon', 'wait',
               'walk', 'wall', 'walnut', 'want', 'warfare', 'warm', 'warrior', 'wash', 'wasp', 'waste', 'water', 'wave',
               'way', 'wealth', 'weapon', 'wear', 'weasel', 'weather', 'web', 'wedding', 'weekend', 'weird', 'welcome',
               'west', 'wet', 'whale', 'what', 'wheat', 'wheel', 'when', 'where', 'whip', 'whisper', 'wide', 'width',
               'wife', 'wild', 'will', 'win', 'window', 'wine', 'wing', 'wink', 'winner', 'winter', 'wire', 'wisdom',
               'wise', 'wish', 'witness', 'wolf', 'woman', 'wonder', 'wood', 'wool', 'word', 'work', 'world', 'worry',
               'worth', 'wrap', 'wreck', 'wrestle', 'wrist', 'write', 'wrong', 'yard', 'year', 'yellow', 'you', 'young',
               'youth', 'zebra', 'zero', 'zone', 'zoo'}

monero_wordlist = {'abbey', 'abducts', 'ability', 'ablaze', 'abnormal', 'abort', 'abrasive', 'absorb', 'abyss',
                   'academy', 'aces', 'aching', 'acidic', 'acoustic', 'acquire', 'across', 'actress', 'acumen', 'adapt',
                   'addicted', 'adept', 'adhesive', 'adjust', 'adopt', 'adrenalin', 'adult', 'adventure', 'aerial',
                   'afar', 'affair', 'afield', 'afloat', 'afoot', 'afraid', 'after', 'against', 'agenda', 'aggravate',
                   'agile', 'aglow', 'agnostic', 'agony', 'agreed', 'ahead', 'aided', 'ailments', 'aimless', 'airport',
                   'aisle', 'ajar', 'akin', 'alarms', 'album', 'alchemy', 'alerts', 'algebra', 'alkaline', 'alley',
                   'almost', 'aloof', 'alpine', 'already', 'also', 'altitude', 'alumni', 'always', 'amaze', 'ambush',
                   'amended', 'amidst', 'ammo', 'amnesty', 'among', 'amply', 'amused', 'anchor', 'android', 'anecdote',
                   'angled', 'ankle', 'annoyed', 'answers', 'antics', 'anvil', 'anxiety', 'anybody', 'apart', 'apex',
                   'aphid', 'aplomb', 'apology', 'apply', 'apricot', 'aptitude', 'aquarium', 'arbitrary', 'archer',
                   'ardent', 'arena', 'argue', 'arises', 'army', 'around', 'arrow', 'arsenic', 'artistic', 'ascend',
                   'ashtray', 'aside', 'asked', 'asleep', 'aspire', 'assorted', 'asylum', 'athlete', 'atlas', 'atom',
                   'atrium', 'attire', 'auburn', 'auctions', 'audio', 'august', 'aunt', 'austere', 'autumn', 'avatar',
                   'avidly', 'avoid', 'awakened', 'awesome', 'awful', 'awkward', 'awning', 'awoken', 'axes', 'axis',
                   'axle', 'aztec', 'azure', 'baby', 'bacon', 'badge', 'baffles', 'bagpipe', 'bailed', 'bakery',
                   'balding', 'bamboo', 'banjo', 'baptism', 'basin', 'batch', 'bawled', 'bays', 'because', 'beer',
                   'befit', 'begun', 'behind', 'being', 'below', 'bemused', 'benches', 'berries', 'bested', 'betting',
                   'bevel', 'beware', 'beyond', 'bias', 'bicycle', 'bids', 'bifocals', 'biggest', 'bikini', 'bimonthly',
                   'binocular', 'biology', 'biplane', 'birth', 'biscuit', 'bite', 'biweekly', 'blender', 'blip',
                   'bluntly', 'boat', 'bobsled', 'bodies', 'bogeys', 'boil', 'boldly', 'bomb', 'border', 'boss', 'both',
                   'bounced', 'bovine', 'bowling', 'boxes', 'boyfriend', 'broken', 'brunt', 'bubble', 'buckets',
                   'budget', 'buffet', 'bugs', 'building', 'bulb', 'bumper', 'bunch', 'business', 'butter', 'buying',
                   'buzzer', 'bygones', 'byline', 'bypass', 'cabin', 'cactus', 'cadets', 'cafe', 'cage', 'cajun',
                   'cake', 'calamity', 'camp', 'candy', 'casket', 'catch', 'cause', 'cavernous', 'cease', 'cedar',
                   'ceiling', 'cell', 'cement', 'cent', 'certain', 'chlorine', 'chrome', 'cider', 'cigar', 'cinema',
                   'circle', 'cistern', 'citadel', 'civilian', 'claim', 'click', 'clue', 'coal', 'cobra', 'cocoa',
                   'code', 'coexist', 'coffee', 'cogs', 'cohesive', 'coils', 'colony', 'comb', 'cool', 'copy',
                   'corrode', 'costume', 'cottage', 'cousin', 'cowl', 'criminal', 'cube', 'cucumber', 'cuddled',
                   'cuffs', 'cuisine', 'cunning', 'cupcake', 'custom', 'cycling', 'cylinder', 'cynical', 'dabbing',
                   'dads', 'daft', 'dagger', 'daily', 'damp', 'dangerous', 'dapper', 'darted', 'dash', 'dating',
                   'dauntless', 'dawn', 'daytime', 'dazed', 'debut', 'decay', 'dedicated', 'deepest', 'deftly',
                   'degrees', 'dehydrate', 'deity', 'dejected', 'delayed', 'demonstrate', 'dented', 'deodorant',
                   'depth', 'desk', 'devoid', 'dewdrop', 'dexterity', 'dialect', 'dice', 'diet', 'different', 'digit',
                   'dilute', 'dime', 'dinner', 'diode', 'diplomat', 'directed', 'distance', 'ditch', 'divers', 'dizzy',
                   'doctor', 'dodge', 'does', 'dogs', 'doing', 'dolphin', 'domestic', 'donuts', 'doorway', 'dormant',
                   'dosage', 'dotted', 'double', 'dove', 'down', 'dozen', 'dreams', 'drinks', 'drowning', 'drunk',
                   'drying', 'dual', 'dubbed', 'duckling', 'dude', 'duets', 'duke', 'dullness', 'dummy', 'dunes',
                   'duplex', 'duration', 'dusted', 'duties', 'dwarf', 'dwelt', 'dwindling', 'dying', 'dynamite',
                   'dyslexic', 'each', 'eagle', 'earth', 'easy', 'eating', 'eavesdrop', 'eccentric', 'echo', 'eclipse',
                   'economics', 'ecstatic', 'eden', 'edgy', 'edited', 'educated', 'eels', 'efficient', 'eggs',
                   'egotistic', 'eight', 'either', 'eject', 'elapse', 'elbow', 'eldest', 'eleven', 'elite', 'elope',
                   'else', 'eluded', 'emails', 'ember', 'emerge', 'emit', 'emotion', 'empty', 'emulate', 'energy',
                   'enforce', 'enhanced', 'enigma', 'enjoy', 'enlist', 'enmity', 'enough', 'enraged', 'ensign',
                   'entrance', 'envy', 'epoxy', 'equip', 'erase', 'erected', 'erosion', 'error', 'eskimos', 'espionage',
                   'essential', 'estate', 'etched', 'eternal', 'ethics', 'etiquette', 'evaluate', 'evenings', 'evicted',
                   'evolved', 'examine', 'excess', 'exhale', 'exit', 'exotic', 'exquisite', 'extra', 'exult', 'fabrics',
                   'factual', 'fading', 'fainted', 'faked', 'fall', 'family', 'fancy', 'farming', 'fatal', 'faulty',
                   'fawns', 'faxed', 'fazed', 'feast', 'february', 'federal', 'feel', 'feline', 'females', 'fences',
                   'ferry', 'festival', 'fetches', 'fever', 'fewest', 'fiat', 'fibula', 'fictional', 'fidget', 'fierce',
                   'fifteen', 'fight', 'films', 'firm', 'fishing', 'fitting', 'five', 'fixate', 'fizzle', 'fleet',
                   'flippant', 'flying', 'foamy', 'focus', 'foes', 'foggy', 'foiled', 'folding', 'fonts', 'foolish',
                   'fossil', 'fountain', 'fowls', 'foxes', 'foyer', 'framed', 'friendly', 'frown', 'fruit', 'frying',
                   'fudge', 'fuel', 'fugitive', 'fully', 'fuming', 'fungal', 'furnished', 'fuselage', 'future', 'fuzzy',
                   'gables', 'gadget', 'gags', 'gained', 'galaxy', 'gambit', 'gang', 'gasp', 'gather', 'gauze', 'gave',
                   'gawk', 'gaze', 'gearbox', 'gecko', 'geek', 'gels', 'gemstone', 'general', 'geometry', 'germs',
                   'gesture', 'getting', 'geyser', 'ghetto', 'ghost', 'giant', 'giddy', 'gifts', 'gigantic', 'gills',
                   'gimmick', 'ginger', 'girth', 'giving', 'glass', 'gleeful', 'glide', 'gnaw', 'gnome', 'goat',
                   'goblet', 'godfather', 'goes', 'goggles', 'going', 'goldfish', 'gone', 'goodbye', 'gopher',
                   'gorilla', 'gossip', 'gotten', 'gourmet', 'governing', 'gown', 'greater', 'grunt', 'guarded',
                   'guest', 'guide', 'gulp', 'gumball', 'guru', 'gusts', 'gutter', 'guys', 'gymnast', 'gypsy', 'gyrate',
                   'habitat', 'hacksaw', 'haggled', 'hairy', 'hamburger', 'happens', 'hashing', 'hatchet', 'haunted',
                   'having', 'hawk', 'haystack', 'hazard', 'hectare', 'hedgehog', 'heels', 'hefty', 'height', 'hemlock',
                   'hence', 'heron', 'hesitate', 'hexagon', 'hickory', 'hiding', 'highway', 'hijack', 'hiker', 'hills',
                   'himself', 'hinder', 'hippo', 'hire', 'history', 'hitched', 'hive', 'hoax', 'hobby', 'hockey',
                   'hoisting', 'hold', 'honked', 'hookup', 'hope', 'hornet', 'hospital', 'hotel', 'hounded', 'hover',
                   'howls', 'hubcaps', 'huddle', 'huge', 'hull', 'humid', 'hunter', 'hurried', 'husband', 'huts',
                   'hybrid', 'hydrogen', 'hyper', 'iceberg', 'icing', 'icon', 'identity', 'idiom', 'idled', 'idols',
                   'igloo', 'ignore', 'iguana', 'illness', 'imagine', 'imbalance', 'imitate', 'impel', 'inactive',
                   'inbound', 'incur', 'industrial', 'inexact', 'inflamed', 'ingested', 'initiate', 'injury', 'inkling',
                   'inline', 'inmate', 'innocent', 'inorganic', 'input', 'inquest', 'inroads', 'insult', 'intended',
                   'inundate', 'invoke', 'inwardly', 'ionic', 'irate', 'iris', 'irony', 'irritate', 'island',
                   'isolated', 'issued', 'italics', 'itches', 'items', 'itinerary', 'itself', 'ivory', 'jabbed',
                   'jackets', 'jaded', 'jagged', 'jailed', 'jamming', 'january', 'jargon', 'jaunt', 'javelin', 'jaws',
                   'jazz', 'jeans', 'jeers', 'jellyfish', 'jeopardy', 'jerseys', 'jester', 'jetting', 'jewels',
                   'jigsaw', 'jingle', 'jittery', 'jive', 'jobs', 'jockey', 'jogger', 'joining', 'joking', 'jolted',
                   'jostle', 'journal', 'joyous', 'jubilee', 'judge', 'juggled', 'juicy', 'jukebox', 'july', 'jump',
                   'junk', 'jury', 'justice', 'juvenile', 'kangaroo', 'karate', 'keep', 'kennel', 'kept', 'kernels',
                   'kettle', 'keyboard', 'kickoff', 'kidneys', 'king', 'kiosk', 'kisses', 'kitchens', 'kiwi',
                   'knapsack', 'knee', 'knife', 'knowledge', 'knuckle', 'koala', 'laboratory', 'ladder', 'lagoon',
                   'lair', 'lakes', 'lamb', 'language', 'laptop', 'large', 'last', 'later', 'launching', 'lava',
                   'lawsuit', 'layout', 'lazy', 'lectures', 'ledge', 'leech', 'left', 'legion', 'leisure', 'lemon',
                   'lending', 'leopard', 'lesson', 'lettuce', 'lexicon', 'liar', 'library', 'licks', 'lids', 'lied',
                   'lifestyle', 'light', 'likewise', 'lilac', 'limits', 'linen', 'lion', 'lipstick', 'liquid', 'listen',
                   'lively', 'loaded', 'lobster', 'locker', 'lodge', 'lofty', 'logic', 'loincloth', 'long', 'looking',
                   'lopped', 'lordship', 'losing', 'lottery', 'loudly', 'love', 'lower', 'loyal', 'lucky', 'luggage',
                   'lukewarm', 'lullaby', 'lumber', 'lunar', 'lurk', 'lush', 'luxury', 'lymph', 'lynx', 'lyrics',
                   'macro', 'madness', 'magically', 'mailed', 'major', 'makeup', 'malady', 'mammal', 'maps',
                   'masterful', 'match', 'maul', 'maverick', 'maximum', 'mayor', 'maze', 'meant', 'mechanic',
                   'medicate', 'meeting', 'megabyte', 'melting', 'memoir', 'menu', 'merger', 'mesh', 'metro', 'mews',
                   'mice', 'midst', 'mighty', 'mime', 'mirror', 'misery', 'mittens', 'mixture', 'moat', 'mobile',
                   'mocked', 'mohawk', 'moisture', 'molten', 'moment', 'money', 'moon', 'mops', 'morsel', 'mostly',
                   'motherly', 'mouth', 'movement', 'mowing', 'much', 'muddy', 'muffin', 'mugged', 'mullet', 'mumble',
                   'mundane', 'muppet', 'mural', 'musical', 'muzzle', 'myriad', 'mystery', 'myth', 'nabbing', 'nagged',
                   'nail', 'names', 'nanny', 'napkin', 'narrate', 'nasty', 'natural', 'nautical', 'navy', 'nearby',
                   'necklace', 'needed', 'negative', 'neither', 'neon', 'nephew', 'nerves', 'nestle', 'network',
                   'neutral', 'never', 'newt', 'nexus', 'nibs', 'niche', 'niece', 'nifty', 'nightly', 'nimbly',
                   'nineteen', 'nirvana', 'nitrogen', 'nobody', 'nocturnal', 'nodes', 'noises', 'nomad', 'noodles',
                   'northern', 'nostril', 'noted', 'nouns', 'novelty', 'nowhere', 'nozzle', 'nuance', 'nucleus',
                   'nudged', 'nugget', 'nuisance', 'null', 'number', 'nuns', 'nurse', 'nutshell', 'nylon', 'oaks',
                   'oars', 'oasis', 'oatmeal', 'obedient', 'object', 'obliged', 'obnoxious', 'observant', 'obtains',
                   'obvious', 'occur', 'ocean', 'october', 'odds', 'odometer', 'offend', 'often', 'oilfield',
                   'ointment', 'okay', 'older', 'olive', 'olympics', 'omega', 'omission', 'omnibus', 'onboard',
                   'oncoming', 'oneself', 'ongoing', 'onion', 'online', 'onslaught', 'onto', 'onward', 'oozed',
                   'opacity', 'opened', 'opposite', 'optical', 'opus', 'orange', 'orbit', 'orchid', 'orders', 'organs',
                   'origin', 'ornament', 'orphans', 'oscar', 'ostrich', 'otherwise', 'otter', 'ouch', 'ought', 'ounce',
                   'ourselves', 'oust', 'outbreak', 'oval', 'oven', 'owed', 'owls', 'owner', 'oxidant', 'oxygen',
                   'oyster', 'ozone', 'pact', 'paddles', 'pager', 'pairing', 'palace', 'pamphlet', 'pancakes', 'paper',
                   'paradise', 'pastry', 'patio', 'pause', 'pavements', 'pawnshop', 'payment', 'peaches', 'pebbles',
                   'peculiar', 'pedantic', 'peeled', 'pegs', 'pelican', 'pencil', 'people', 'pepper', 'perfect',
                   'pests', 'petals', 'phase', 'pheasants', 'phone', 'phrases', 'physics', 'piano', 'picked', 'pierce',
                   'pigment', 'piloted', 'pimple', 'pinched', 'pioneer', 'pipeline', 'pirate', 'pistons', 'pitched',
                   'pivot', 'pixels', 'pizza', 'playful', 'pledge', 'pliers', 'plotting', 'plus', 'plywood', 'poaching',
                   'pockets', 'podcast', 'poetry', 'point', 'poker', 'polar', 'ponies', 'pool', 'popular', 'portents',
                   'possible', 'potato', 'pouch', 'poverty', 'powder', 'pram', 'present', 'pride', 'problems', 'pruned',
                   'prying', 'psychic', 'public', 'puck', 'puddle', 'puffin', 'pulp', 'pumpkins', 'punch', 'puppy',
                   'purged', 'push', 'putty', 'puzzled', 'pylons', 'pyramid', 'python', 'queen', 'quick', 'quote',
                   'rabbits', 'racetrack', 'radar', 'rafts', 'rage', 'railway', 'raking', 'rally', 'ramped', 'randomly',
                   'rapid', 'rarest', 'rash', 'rated', 'ravine', 'rays', 'razor', 'react', 'rebel', 'recipe', 'reduce',
                   'reef', 'refer', 'regular', 'reheat', 'reinvest', 'rejoices', 'rekindle', 'relic', 'remedy',
                   'renting', 'reorder', 'repent', 'request', 'reruns', 'rest', 'return', 'reunion', 'revamp', 'rewind',
                   'rhino', 'rhythm', 'ribbon', 'richly', 'ridges', 'rift', 'rigid', 'rims', 'ringing', 'riots',
                   'ripped', 'rising', 'ritual', 'river', 'roared', 'robot', 'rockets', 'rodent', 'rogue', 'roles',
                   'romance', 'roomy', 'roped', 'roster', 'rotate', 'rounded', 'rover', 'rowboat', 'royal', 'ruby',
                   'rudely', 'ruffled', 'rugged', 'ruined', 'ruling', 'rumble', 'runway', 'rural', 'rustled',
                   'ruthless', 'sabotage', 'sack', 'sadness', 'safety', 'saga', 'sailor', 'sake', 'salads', 'sample',
                   'sanity', 'sapling', 'sarcasm', 'sash', 'satin', 'saucepan', 'saved', 'sawmill', 'saxophone',
                   'sayings', 'scamper', 'scenic', 'school', 'science', 'scoop', 'scrub', 'scuba', 'seasons', 'second',
                   'sedan', 'seeded', 'segments', 'seismic', 'selfish', 'semifinal', 'sensible', 'september',
                   'sequence', 'serving', 'session', 'setup', 'seventh', 'sewage', 'shackles', 'shelter', 'shipped',
                   'shocking', 'shrugged', 'shuffled', 'shyness', 'siblings', 'sickness', 'sidekick', 'sieve',
                   'sifting', 'sighting', 'silk', 'simplest', 'sincerely', 'sipped', 'siren', 'situated', 'sixteen',
                   'sizes', 'skater', 'skew', 'skirting', 'skulls', 'skydive', 'slackens', 'sleepless', 'slid',
                   'slower', 'slug', 'smash', 'smelting', 'smidgen', 'smog', 'smuggled', 'snake', 'sneeze', 'sniff',
                   'snout', 'snug', 'soapy', 'sober', 'soccer', 'soda', 'software', 'soggy', 'soil', 'solved',
                   'somewhere', 'sonic', 'soothe', 'soprano', 'sorry', 'southern', 'sovereign', 'sowed', 'soya',
                   'space', 'speedy', 'sphere', 'spiders', 'splendid', 'spout', 'sprig', 'spud', 'spying', 'square',
                   'stacking', 'stellar', 'stick', 'stockpile', 'strained', 'stunning', 'stylishly', 'subtly',
                   'succeed', 'suddenly', 'suede', 'suffice', 'sugar', 'suitcase', 'sulking', 'summon', 'sunken',
                   'superior', 'surfer', 'sushi', 'suture', 'swagger', 'swept', 'swiftly', 'sword', 'swung', 'syllabus',
                   'symptoms', 'syndrome', 'syringe', 'system', 'taboo', 'tacit', 'tadpoles', 'tagged', 'tail', 'taken',
                   'talent', 'tamper', 'tanks', 'tapestry', 'tarnished', 'tasked', 'tattoo', 'taunts', 'tavern',
                   'tawny', 'taxi', 'teardrop', 'technical', 'tedious', 'teeming', 'tell', 'template', 'tender',
                   'tepid', 'tequila', 'terminal', 'testing', 'tether', 'textbook', 'thaw', 'theatrics', 'thirsty',
                   'thorn', 'threaten', 'thumbs', 'thwart', 'ticket', 'tidy', 'tiers', 'tiger', 'tilt', 'timber',
                   'tinted', 'tipsy', 'tirade', 'tissue', 'titans', 'toaster', 'tobacco', 'today', 'toenail', 'toffee',
                   'together', 'toilet', 'token', 'tolerant', 'tomorrow', 'tonic', 'toolbox', 'topic', 'torch',
                   'tossed', 'total', 'touchy', 'towel', 'toxic', 'toyed', 'trash', 'trendy', 'tribal', 'trolling',
                   'truth', 'trying', 'tsunami', 'tubes', 'tucks', 'tudor', 'tuesday', 'tufts', 'tugs', 'tuition',
                   'tulips', 'tumbling', 'tunnel', 'turnip', 'tusks', 'tutor', 'tuxedo', 'twang', 'tweezers', 'twice',
                   'twofold', 'tycoon', 'typist', 'tyrant', 'ugly', 'ulcers', 'ultimate', 'umbrella', 'umpire',
                   'unafraid', 'unbending', 'uncle', 'under', 'uneven', 'unfit', 'ungainly', 'unhappy', 'union',
                   'unjustly', 'unknown', 'unlikely', 'unmask', 'unnoticed', 'unopened', 'unplugs', 'unquoted',
                   'unrest', 'unsafe', 'until', 'unusual', 'unveil', 'unwind', 'unzip', 'upbeat', 'upcoming', 'update',
                   'upgrade', 'uphill', 'upkeep', 'upload', 'upon', 'upper', 'upright', 'upstairs', 'uptight',
                   'upwards', 'urban', 'urchins', 'urgent', 'usage', 'useful', 'usher', 'using', 'usual', 'utensils',
                   'utility', 'utmost', 'utopia', 'uttered', 'vacation', 'vague', 'vain', 'value', 'vampire', 'vane',
                   'vapidly', 'vary', 'vastness', 'vats', 'vaults', 'vector', 'veered', 'vegan', 'vehicle', 'vein',
                   'velvet', 'venomous', 'verification', 'vessel', 'veteran', 'vexed', 'vials', 'vibrate', 'victim',
                   'video', 'viewpoint', 'vigilant', 'viking', 'village', 'vinegar', 'violin', 'vipers', 'virtual',
                   'visited', 'vitals', 'vivid', 'vixen', 'vocal', 'vogue', 'voice', 'volcano', 'vortex', 'voted',
                   'voucher', 'vowels', 'voyage', 'vulture', 'wade', 'waffle', 'wagtail', 'waist', 'waking', 'wallets',
                   'wanted', 'warped', 'washing', 'water', 'waveform', 'waxing', 'wayside', 'weavers', 'website',
                   'wedge', 'weekday', 'weird', 'welders', 'went', 'wept', 'were', 'western', 'wetsuit', 'whale',
                   'when', 'whipped', 'whole', 'wickets', 'width', 'wield', 'wife', 'wiggle', 'wildly', 'winter',
                   'wipeout', 'wiring', 'wise', 'withdrawn', 'wives', 'wizard', 'wobbly', 'woes', 'woken', 'wolf',
                   'womanly', 'wonders', 'woozy', 'worry', 'wounded', 'woven', 'wrap', 'wrist', 'wrong', 'yacht',
                   'yahoo', 'yanks', 'yard', 'yawning', 'yearbook', 'yellow', 'yesterday', 'yeti', 'yields', 'yodel',
                   'yoga', 'younger', 'yoyo', 'zapped', 'zeal', 'zebra', 'zero', 'zesty', 'zigzags', 'zinger',
                   'zippers', 'zodiac', 'zombie', 'zones', 'zoom'}


def overlapping_offset(start, end, existing_offsets):
    for existing_start, existing_end in existing_offsets:
        if existing_start <= start <= existing_end or existing_start <= end <= existing_end:
            return True
    return False


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
        print(f"Unicode decode error in longseed processing: {err}")
    except Exception as err:
        print(f"Unexpected error in longseed processing: {err}")


def file_data_search(filedata, filepath, printablesize):
    found_addresses = []
    found_seedstrings_count = 0
    start_time = time.time()
    last_check_time = start_time

    used_offsets = []
    used_patterns = []
    match_offset = []

    for pattern, description in patterns:
        current_time = time.time()
        if current_time - last_check_time > 10:
            last_check_time = current_time
            printabletime = datetime.datetime.now().strftime("%H:%M:%S")
            print(f"{printabletime}: Still processing {filepath} ({printablesize}). Currently searching for: {description}.")
        for match in pattern.finditer(filedata):
            start, end = match.start(), match.end()

            if description == 'BIP-39 Seed String':
                words = match.group().decode('utf8').lower().split()
                if len(set(words)) == 12 and (all(word in wordlist for word in words) or all(word in monero_wordlist for word in words)):
                    seed_string = ' '.join(words)
                    used_patterns.append('BIP-39 Seed String')
                    found_addresses.append(seed_string)
                    match_offset.append(start)
                    found_seedstrings_count += 1

            else:
                matched_string = filedata[start:end].decode("utf-8")
                if Validator.validate_address(matched_string, description):
                    if not overlapping_offset(start, end, used_offsets):
                        if description == 'Ethereum Address' and Validator.ethereum_check_if_unverifyable(matched_string):
                            used_patterns.append('Ethereum Address (unverifyable)')
                        else:
                            used_patterns.append(description)
                        found_addresses.append(matched_string)
                        match_offset.append(start)
                        used_offsets.append([start, end])

    if found_seedstrings_count == 0:
        find_bip39_word_sequences(filedata, used_patterns, found_addresses, match_offset)

    return used_patterns, found_addresses, match_offset


def read_in_chunks(file_instance, overlap_size=1024):
    chunk_size = int((psutil.virtual_memory().available / int(multiprocessing.cpu_count() - 2)) * 0.90)
    with open(file_instance.getfilepath(), 'rb') as file:
        prev_chunk_end = b''
        while True:
            chunk = file.read(chunk_size)
            if not chunk:
                break
            combined_chunk = prev_chunk_end + chunk
            yield combined_chunk
            prev_chunk_end = chunk[-overlap_size:]


def process_file(inputmaxsize, excluded_paths, archive_path, temppath, file_path):
    file_instance = FileHandler(file_path)
    filesize = file_instance.getfilesize()

    if file_instance.check_if_excluded(excluded_paths):
        return False
    printabletime = datetime.datetime.now().strftime("%H:%M:%S")

    if archive_path:
        file_path_printable = archive_path.replace("\\", "/")
    else:
        file_path_printable = file_path.replace("\\", "/")

    print(f"{printabletime}: Scanning: {file_path_printable} ({file_instance.getfilesize_printable()})")
    found_wallet_file = WalletFinder.findwallets(file_path)
    found_wallet_path = WalletFinder.findwalletpath(file_path)

    if file_instance.filecheck(inputmaxsize):
        return False

    try:
        results = []
        supported_archives = ['.zip', '.7z', '.tar', '.gz', '.tgz', '.rar']

        if file_instance.getfileextension() in supported_archives:
            print(f"{printabletime}: Extracting files from: {file_path_printable}")
            results = process_archive_file(inputmaxsize, excluded_paths, temppath, file_path)
        else:
            file_data = file_instance.getspecialfiledata()

            if file_data:
                results = file_data_search(file_data, file_path, file_instance.getfilesize_printable())

            elif file_instance.getfilesize() > 1024 * 1024 * 1024:
                combined_results = [[], [], []]
                for file_data in read_in_chunks(file_instance):
                    chunk_results = file_data_search(file_data, file_path, file_instance.getfilesize_printable())
                    combined_results = [combined + chunk for combined, chunk in zip(combined_results, chunk_results)]

                results = combined_results

            else:
                with open(file_instance.getfilepath(), 'rb') as file, mmap(file.fileno(), 0, access=ACCESS_READ) as mmapfile:
                    # with open(file_instance.getfilepath(), 'rb') as file:
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
        printabletime = datetime.datetime.now().strftime("%H:%M:%S")

        print(f"{printabletime}: Done with: {file_path_printable} ({file_instance.getfilesize_printable()})")

        if archive_path or file_instance.getfileextension() in supported_archives:
            return results, archive_path, filesize
        else:
            return results, file_path, filesize

    except Exception as err:
        print(f"An error occurred while processing the file: {err}")
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
        print(f"Error extracting archive {archive_file_path}: {err}")


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
                    archive_file_path_printable = os.path.join(archive_file_path, relative_path).replace('/', "\\")

                    file_results = process_file(inputmaxsize, excluded_paths, archive_file_path_printable, temppath_, full_path)
                    if file_results:
                        results.append(file_results)

        return results

    except Exception as err:
        print(f"Error reading archive: {err}")
