"""_val.py — does desc10_58 actually validate against the genuine device blobs?"""
import sys, os, hashlib
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import desc10_58 as D
try:
    print('--- self_test ---')
    D.self_test()
except Exception as e:
    print('self_test raised:', repr(e))
print()
print('--- validate_against_device ---')
try:
    r = D.validate_against_device()
    print('result:', r)
except Exception as e:
    print('validate raised:', repr(e))
