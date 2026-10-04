#!/usr/bin/env python3
"""analyze_dex.py - androguard-based analysis of the adjust SDK dexes.

For each (dex, tag) pair:
  - lists defined classes in com/adjust/sdk/** (and given obfuscated prefixes)
  - dumps full instruction listing of the sig package classes + any class that
    references key strings (adj_signing_id / headers_id / native_version /
    client_sdk / 5.0.7 / no_sdkclick ...)
  - writes per-class string constants for all com/adjust/sdk classes to
    <tag>_adjust_strings.txt  (class -> strings, sorted unique)
Outputs into OUT (sdk_diff dir).
"""
import os
import sys

from loguru import logger
logger.remove()

from androguard.core.dex import DEX

OUT = os.path.dirname(os.path.abspath(__file__))

TARGETS = [
    ('penti_dex/classes3.dex', 'p57_c3'),
    ('penti_dex/classes6.dex', 'p57_c6'),
    ('creditsea_dex/classes.dex', 'c58_c1'),
]

KEY_STRINGS = {'adj_signing_id', 'headers_id', 'native_version', 'client_sdk',
               '5.0.7', '5.0.1', '5.0.0', 'no_sdkclick', 'sdk_click',
               'install_referrer', 'referrer_api', 'activity_kind',
               'initiating_package_name', 'store_name_from_system',
               'session_count', 'tracking_enabled', 'updated_at',
               'adj_verification', 'gps_adid_src', 'android_uuid'}


def u128(buf, off):
    r = 0; sh = 0
    while True:
        b = buf[off]; off += 1
        r |= (b & 0x7F) << sh
        if not (b & 0x80):
            return r, off
        sh += 7


def string_consts(dex):
    """String constants in code, as {string: [class names]}."""
    refs = {}
    for c in dex.get_classes():
        cn = c.get_name()
        for m in c.get_methods():
            code = m.get_code()
            if not code:
                continue
            for i in code.get_bc().get_instructions():
                if i.get_name().startswith('const-string'):
                    out = i.get_output()
                    # output like 'v0, "the string"' -> parse quoted part
                    p = out.find('"')
                    if p < 0:
                        continue
                    s = out[p + 1:out.rfind('"')]
                    refs.setdefault(s, set()).add(cn)
    return refs


def dump_class(dex, cname, fh):
    for c in dex.get_classes():
        if c.get_name() != cname:
            continue
        fh.write('#' * 70 + '\n# CLASS %s\n' % cname)
        for f in c.get_fields():
            fh.write('FIELD %s %s\n' % (f.get_access_flags_string(), f.get_descriptor() if hasattr(f, 'get_descriptor') else f.get_name()))
        for m in c.get_methods():
            fh.write('\n---- METHOD %s %s(%s) %s ----\n' % (
                m.get_access_flags_string(), m.get_name(),
                m.get_descriptor(), ''))
            code = m.get_code()
            if not code:
                fh.write('  (no code)\n')
                continue
            for i in code.get_bc().get_instructions():
                fh.write('  %-22s %s\n' % (i.get_name(), i.get_output()))
        return True
    return False


def main():
    for rel, tag in TARGETS:
        path = os.path.join(OUT, rel)
        print('== %s (%s)' % (rel, tag))
        data = open(path, 'rb').read()
        dex = DEX(data)
        # 1. defined adjust classes
        adj_classes = sorted(c.get_name() for c in dex.get_classes()
                             if c.get_name().startswith('Lcom/adjust/sdk/'))
        print('  defined com/adjust/sdk/** classes: %d' % len(adj_classes))
        with open(os.path.join(OUT, tag + '_adjust_classes.txt'), 'w') as f:
            f.write('\n'.join(adj_classes))
        sig_classes = [c for c in adj_classes if '/sig/' in c]
        print('  sig classes: %s' % [c.split('/')[-1] for c in sig_classes])

        # 2. string constants referenced
        refs = string_consts(dex)
        adj_strings = {}
        for s, cls in refs.items():
            a = [x for x in cls if x.startswith('Lcom/adjust/sdk/')]
            if a:
                adj_strings[s] = sorted(a)
        with open(os.path.join(OUT, tag + '_adjust_strings.txt'), 'w',
                  encoding='utf-8', errors='surrogatepass') as f:
            for s in sorted(adj_strings):
                f.write('%s\t%s\n' % (s, ';'.join(adj_strings[s])))
        print('  adjust-referenced strings: %d' % len(adj_strings))

        # 3. classes referencing key strings -> dump
        hits = {}
        for k in KEY_STRINGS:
            hits[k] = adj_strings.get(k, [])
            print('  ref[%s]: %s' % (k, [c.split('/')[-1] for c in hits[k]]))
        dump_targets = set()
        for k in KEY_STRINGS:
            dump_targets.update(hits[k])
        dump_targets.update(sig_classes)
        with open(os.path.join(OUT, tag + '_sig_dump.txt'), 'w') as f:
            for cn in sorted(dump_targets):
                if not dump_class(dex, cn, f):
                    f.write('MISSING %s\n' % cn)
        print('  dumped %d classes -> %s_sig_dump.txt' % (len(dump_targets), tag))


if __name__ == '__main__':
    main()
