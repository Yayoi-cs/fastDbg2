import gdb
import hashlib
import json
import os
import pathlib
import re
import struct

libc = os.environ['FASTDBG_LIBC_DEBUG']
loader = os.environ['FASTDBG_LOADER_DEBUG']
output = os.environ['FASTDBG_PROFILE_OUTPUT']
malloc_source = open(os.environ['FASTDBG_MALLOC_SOURCE'], 'rb').read()
arena_source = open(os.environ['FASTDBG_ARENA_SOURCE'], 'rb').read()
malloc_sha = hashlib.sha256(malloc_source).hexdigest()
arena_sha = hashlib.sha256(arena_source).hexdigest()
sources = json.loads((pathlib.Path(__file__).parent / 'source_semantics.json').read_text())
matched = [s for s in sources if s['MallocSourceSHA256'] == malloc_sha and s['ArenaSourceSHA256'] == arena_sha]
models = {json.dumps({k: v for k, v in s.items() if k != 'Source'}, sort_keys=True) for s in matched}
if len(models) != 1:
    raise ValueError('allocator source has absent or conflicting reviewed semantics')
source_model = matched[0]
semantics = dict(source_model['Semantics'])

def elf_data(path):
    data = open(path, 'rb').read()
    if data[:7] != b'\x7fELF\x02\x01\x01' or struct.unpack_from('<H', data, 18)[0] != 62:
        raise ValueError('requires little-endian AMD64 ELF64')
    offset = struct.unpack_from('<Q', data, 40)[0]
    size, count, names = struct.unpack_from('<HHH', data, 58)
    if size != 64 or not count or names >= count or offset + count * size > len(data):
        raise ValueError('unsupported section table')
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, offset + i * size) for i in range(count)]
    name_section = sections[names]
    strings = data[name_section[4]:name_section[4] + name_section[5]]
    ids = []
    symbols = {}
    for section in sections:
        name = strings[section[0]:].split(b'\0', 1)[0]
        raw = data[section[4]:section[4] + section[5]]
        if name == b'.note.gnu.build-id':
            namesz, descsz, kind = struct.unpack_from('<III', raw)
            if namesz != 4 or kind != 3 or raw[12:16] != b'GNU\0' or 16 + descsz > len(raw):
                raise ValueError('invalid GNU build ID')
            ids.append(raw[16:16 + descsz].hex())
        if section[1] not in [2, 11]:
            continue
        if section[9] != 24 or len(raw) % 24 or section[6] >= len(sections):
            raise ValueError('invalid symbols')
        linked = sections[section[6]]
        strings_data = data[linked[4]:linked[4] + linked[5]]
        for at in range(0, len(raw), 24):
            nameoff, info, other, shndx, value, length = struct.unpack_from('<IBBHQQ', raw, at)
            if shndx == 0:
                continue
            name = strings_data[nameoff:].split(b'\0', 1)[0].decode()
            if name not in ['main_arena', 'mp_', '__tcache_dummy', 'thread_arena', 'tcache', 'tcache_shutting_down', '_rtld_global']:
                continue
            record = {'Value': value, 'Size': length, 'Type': info & 15}
            if name in symbols and symbols[name] != record:
                raise ValueError('ambiguous symbol ' + name)
            symbols[name] = record
    if len(set(ids)) != 1:
        raise ValueError('requires one complete build ID')
    return ids[0], symbols, hashlib.sha256(data).hexdigest()

def base(t):
    return t.strip_typedefs().unqualified()

def member(t, name, depth=0):
    if depth > 16:
        raise ValueError('anonymous member nesting')
    found = []
    for field in base(t).fields():
        if field.bitsize:
            continue
        if field.bitpos % 8:
            raise ValueError('non-byte member')
        if field.name == name:
            found.append((field.bitpos // 8, field.type))
        elif field.name is None:
            try:
                offset, kind = member(field.type, name, depth + 1)
                found.append((field.bitpos // 8 + offset, kind))
            except KeyError:
                pass
    if not found:
        raise KeyError(name)
    if len(found) != 1:
        raise ValueError('ambiguous member ' + name)
    return found[0]

def record(t, names):
    fields = {}
    for name in names:
        offset, kind = member(t, name)
        kind = base(kind)
        count = 1
        if kind.code == gdb.TYPE_CODE_ARRAY:
            low, high = kind.range()
            if low != 0 or high < low:
                raise ValueError('noncontiguous array')
            count = high - low + 1
            kind = base(kind.target())
        width = kind.sizeof
        if width not in [1, 2, 4, 8] or kind.code not in [gdb.TYPE_CODE_PTR, gdb.TYPE_CODE_INT, gdb.TYPE_CODE_ENUM, gdb.TYPE_CODE_BOOL]:
            raise ValueError('unsupported field ' + name)
        fields[name] = {'offset': offset, 'width': width, 'count': count, 'stride': width}
    return {'size': t.sizeof, 'fields': fields}

def offset(t, name):
    return member(t, name)[0]

def symbol_type(name):
    symbol = gdb.lookup_static_symbol(name)
    if symbol is None:
        symbol = gdb.lookup_global_symbol(name)
    if symbol is None:
        raise ValueError('missing exact DWARF symbol ' + name)
    return symbol.type

libc_id, libc_symbols, libc_sha = elf_data(libc)
loader_id, loader_symbols, loader_sha = elf_data(loader)
gdb.execute('set auto-load off')
gdb.execute('set debuginfod enabled off')
gdb.execute('file ' + libc)
arena = symbol_type('main_arena')
chunk = base(member(arena, 'top')[1]).target()
cache = symbol_type('tcache').target()
cache_entry = base(member(cache, 'entries')[1]).target().target()
link_map = gdb.lookup_type('struct link_map')
tcb = gdb.lookup_type('tcbhead_t')
pthread = gdb.lookup_type('struct pthread')
dtv = gdb.lookup_type('dtv_t')
slot = gdb.lookup_type('struct dtv_slotinfo')
slot_list = gdb.lookup_type('struct dtv_slotinfo_list')
size_size = gdb.lookup_type('size_t').sizeof
alignment = max(2 * size_size, gdb.lookup_type('long double').alignof)
minimum = (offset(chunk, 'fd_nextsize') + alignment - 1) & ~(alignment - 1)
small_name = b'TCACHE_SMALL_BINS' if semantics['TcacheCounterMode'] == 'num_slots' else b'TCACHE_MAX_BINS'
small_bins = re.findall(rb'^#\s*define\s+' + small_name + rb'\s+(\d+)\s*$', malloc_source, re.M)
large_bins = re.findall(rb'^#\s*define\s+TCACHE_LARGE_BINS\s+(\d+)\s*/\* Up to 4M chunks \*/\s*$', malloc_source, re.M) if semantics['TcacheCounterMode'] == 'num_slots' else [b'0']
if len(small_bins) != 1 or len(large_bins) != 1:
    raise ValueError('source tcache constant declarations changed')
small_normal = re.findall(rb'^#\s*define\s+NSMALLBINS\s+(\d+)\s*$', malloc_source, re.M)
normal_bins = re.findall(rb'^#\s*define\s+NBINS\s+(\d+)\s*$', malloc_source, re.M)
if len(small_normal) != 1 or len(normal_bins) != 1:
    raise ValueError('source normal-bin constant declarations changed')
arena_fields = ['mutex', 'flags', 'top', 'last_remainder', 'bins', 'binmap', 'next', 'next_free', 'attached_threads', 'system_mem', 'max_system_mem']
if source_model['Fastbins']:
    arena_fields += ['fastbinsY', 'have_fastchunks']
mp_fields = ['sbrk_base', semantics['TcacheSmallBinsField'], 'tcache_max_bytes', 'tcache_count']
try:
    member(symbol_type('mp_'), 'hp_pagesize')
    mp_fields.append('hp_pagesize')
except KeyError:
    if source_model['HeapMaxConditional'] and semantics['HeapMaxMode'] == 'huge-pages-times-four':
        semantics['HeapMaxMode'] = 'constant'
    elif semantics['HeapMaxMode'] == 'huge-pages-times-four':
        raise ValueError('unconditional source heap maximum requires hp_pagesize')
symbols_wanted = ['main_arena', 'mp_', 'thread_arena', 'tcache']
inactive, disabled = 0, 0
if semantics['TcacheStateMode'] == 'dummy':
    dummy = symbol_type('__tcache_dummy')
    inactive, disabled = offset(dummy, 'inactive'), offset(dummy, 'disabled')
    symbols_wanted.append('__tcache_dummy')
else:
    symbols_wanted.append('tcache_shutting_down')
profile = {
    'Schema': 1,
    'Name': os.environ.get('FASTDBG_PROFILE_NAME', 'glibc-amd64-' + libc_id[:12]),
    'LibcBuildID': libc_id, 'LoaderBuildID': loader_id,
    'SourceRevision': os.environ.get('FASTDBG_SOURCE_REVISION', 'malloc-sha256-' + malloc_sha),
    'LibcDebugSHA256': libc_sha, 'LoaderDebugSHA256': loader_sha,
    'MallocSourceSHA256': malloc_sha,
    'ArenaSourceSHA256': arena_sha,
    'Layout': {'schema': 1, 'allocator': 'glibc', 'arch': 'amd64', 'endian': 'little', 'pointer': 8,
        'arena': record(arena, arena_fields),
        'chunk': record(chunk, ['mchunk_prev_size', 'mchunk_size', 'fd', 'bk', 'fd_nextsize', 'bk_nextsize']),
        'fast_link': 'safe-link-12' if source_model['Fastbins'] else '', 'tcache': record(cache, [semantics['TcacheCounterMode'], 'entries']),
        'tcache_entry': record(cache_entry, ['next', 'key']), 'tcache_link': 'safe-link-12'},
    'MallocPar': record(symbol_type('mp_'), mp_fields),
    'HeapInfo': record(gdb.lookup_type('heap_info'), ['ar_ptr', 'prev', 'size', 'mprotect_size', 'pagesize']),
    'Symbols': {name: libc_symbols[name] for name in symbols_wanted},
    'DummyInactiveOffset': inactive, 'DummyDisabledOffset': disabled,
    'Semantics': semantics,
    'Constants': {'Alignment': alignment, 'MinChunkSize': minimum, 'ChunkHeaderSize': 2 * size_size, 'SizeFlags': 1 | 2 | 4,
        'HeapMaxSize': 2 * 4 * 1024 * 1024 * gdb.lookup_type('long').sizeof, 'TcacheSmallBinCount': int(small_bins[0]), 'TcacheLargeBinCount': int(large_bins[0]),
        'SmallBinCount': int(small_normal[0]), 'NormalBinCount': int(normal_bins[0]), 'FastBinShift': 4 if source_model['Fastbins'] else 0},
    'TLS': {
        'ThreadSize': pthread.sizeof, 'TCBSize': tcb.sizeof,
        'ThreadSelfOffset': offset(tcb, 'self'), 'ThreadTCBOffset': offset(tcb, 'tcb'),
        'ThreadDTVOffset': offset(tcb, 'dtv'), 'ThreadTIDOffset': offset(pthread, 'tid'),
        'DTVEntrySize': dtv.sizeof, 'DTVGenerationOffset': offset(dtv, 'counter'),
        'DTVPointerOffset': offset(dtv, 'pointer') + offset(member(dtv, 'pointer')[1], 'val'),
        'LinkMapModIDOffset': offset(link_map, 'l_tls_modid'), 'LinkMapStaticOffset': offset(link_map, 'l_tls_offset'),
        'LinkMapBlockSizeOffset': offset(link_map, 'l_tls_blocksize'),
        'SlotListSize': slot_list.sizeof, 'SlotListLengthOffset': offset(slot_list, 'len'),
        'SlotListNextOffset': offset(slot_list, 'next'), 'SlotListEntriesOffset': offset(slot_list, 'slotinfo'),
        'SlotEntrySize': slot.sizeof, 'SlotGenerationOffset': offset(slot, 'gen'), 'SlotMapOffset': offset(slot, 'map')}
}
gdb.execute('file ' + loader)
rtld = gdb.lookup_type('struct rtld_global')
loader_link_map = gdb.lookup_type('struct link_map')
loader_slot = gdb.lookup_type('struct dtv_slotinfo')
loader_slot_list = gdb.lookup_type('struct dtv_slotinfo_list')
profile['TLS'].update({
    'LinkMapSize': loader_link_map.sizeof,
    'LinkMapModIDOffset': offset(loader_link_map, 'l_tls_modid'),
    'LinkMapStaticOffset': offset(loader_link_map, 'l_tls_offset'),
    'LinkMapBlockSizeOffset': offset(loader_link_map, 'l_tls_blocksize'),
    'SlotListSize': loader_slot_list.sizeof, 'SlotListLengthOffset': offset(loader_slot_list, 'len'),
    'SlotListNextOffset': offset(loader_slot_list, 'next'), 'SlotListEntriesOffset': offset(loader_slot_list, 'slotinfo'),
    'SlotEntrySize': loader_slot.sizeof, 'SlotGenerationOffset': offset(loader_slot, 'gen'), 'SlotMapOffset': offset(loader_slot, 'map')})
profile['Symbols']['_rtld_global'] = loader_symbols['_rtld_global']
profile['TLS']['RTLDSlotInfoOffset'] = offset(rtld, '_dl_tls_dtv_slotinfo_list')
profile['TLS']['RTLDGenerationOffset'] = offset(rtld, '_dl_tls_generation')
with open(output, 'w') as stream:
    json.dump(profile, stream, sort_keys=True, indent=2)
    stream.write('\n')
print(output)
