# SPDX-License-Identifier: MIT
"""Cross-check native DUMPBIN linker-member metadata against the raw COFF indices."""
from collections import Counter
import hashlib
import re


def require(value, message):
    if not value:
        raise ValueError(message)


def matches_number(token, value):
    return any(int(token, base) == value for base in [16, 10] if base == 16 or token.isdigit())


def verify_dumpbin(text, index):
    require(len(text.encode('utf-8')) <= 8 * 1024 ** 2, 'Native index evidence cap')
    lines = text.splitlines()
    headers = []
    for i, line in enumerate(lines):
        match = re.fullmatch(r'Archive member name at ([0-9A-Fa-f]+):\s+(.+?)\s*', line.strip())
        if match:
            headers.append((i, int(match[1], 16), match[2].strip()))
    directory_headers = [x for x in headers if x[2] == '/']
    require(len(directory_headers) == 2, 'Native output lacks exactly two archive indices')
    parsed = {}
    for which, (start, offset, _) in zip(['first', 'second'], directory_headers):
        end = next((i for i, _, _ in headers if i > start), len(lines))
        block = [line.strip() for line in lines[start + 1:end]]
        metadata = index['metadata'][which + '_linker_member']
        require(offset == metadata['archive_header_offset'], 'Native index header offset disagreement')
        size_fields = [m[1] for line in block if (m := re.fullmatch(r'([0-9a-fA-F]+) size', line))]
        require(len(size_fields) == 1 and int(size_fields[0], 16) == metadata['size'], 'Native index payload size disagreement')
        markers = [(i, m[1]) for i, line in enumerate(block) if
                   (m := re.fullmatch(r'([0-9a-fA-F]+) public symbols', line))]
        require(len(markers) == 1 and matches_number(markers[0][1], metadata['symbol_count']),
                'Native symbol-count disagreement')
        public_start = markers[0][0]
        def records_after(position, count, pattern):
            records, cursor = [], position + 1
            while len(records) < count and cursor < len(block):
                line = block[cursor]
                cursor += 1
                if not line:
                    continue
                match = re.fullmatch(pattern, line)
                require(match is not None, 'Malformed/incomplete native index record')
                records.append(match.groups())
            require(len(records) == count, 'Truncated native index records')
            return records, cursor
        symbol_rows, cursor = records_after(public_start, metadata['symbol_count'], r'([0-9a-fA-F]+)[ \t]+(\S+)')
        tail = block[cursor:]
        if 'Summary' in tail:
            cut = tail.index('Summary')
            require(not any(tail[:cut]) and all(not line or re.fullmatch(r'[0-9a-fA-F]+ \S+', line) for line in tail[cut + 1:]),
                    'Unknown native summary data')
        else:
            require(not any(tail), 'Extra native index symbols')
        if which == 'first':
            entries = [(name, int(number, 16)) for number, name in symbol_rows]
        else:
            offset_markers = [(i, m[1]) for i, line in enumerate(block) if
                              (m := re.fullmatch(r'([0-9a-fA-F]+) offsets', line))]
            require(len(offset_markers) == 1 and offset_markers[0][0] < public_start and
                    matches_number(offset_markers[0][1], metadata['member_count']), 'Native member-count disagreement')
            offsets, stop = records_after(offset_markers[0][0], metadata['member_count'], r'([0-9a-fA-F]+)[ \t]+([0-9a-fA-F]+)')
            require(stop <= public_start and not any(block[stop:public_start]), 'Unknown native offset-table suffix')
            modes = {10, 16}
            for ordinal, (label, _) in enumerate(offsets, 1):
                modes = {base for base in modes if (base == 16 or label.isdigit()) and int(label, base) == ordinal}
            require(modes, 'Native offset index labels are not consecutive')
            values = [int(value, 16) for _, value in offsets]
            require(values == sorted(index['members_by_header_offset']), 'Native object offsets disagree with archive')
            entries = []
            for label, symbol in symbol_rows:
                ids = {int(label, base) for base in modes if base == 16 or label.isdigit()}
                require(len(ids) == 1 and 1 <= next(iter(ids)) <= len(values), 'Native symbol index invalid/ambiguous')
                entries.append((symbol, values[next(iter(ids)) - 1]))
        # Counters preserve multiplicity; duplicates never overwrite a prior owner.
        require(Counter(entries) == Counter(map(tuple, index['symbol_entries'][which])),
                'Native and byte-parsed index symbol mappings disagree')
        parsed[which] = len(entries)
    return {'native_text_sha256': hashlib.sha256(text.encode('utf-8')).hexdigest(),
            'first_entry_count': parsed['first'], 'second_entry_count': parsed['second'],
            'both_index_entry_multisets_match': True, 'provider_approved': False}
