"""_d10chk.py — authoritative check: does our click claim law reproduce the
genuine d10 for row8, using the correct android_uuid?"""
import binascii, json, sys
sys.path.insert(0, '.')
import mint_pipeline as M

sig = json.load(open('all_signings.json'))
r8 = [r for r in sig if r['ev'] == 22272][0]
gen_padded = binascii.unhexlify(r8['d10'])
gen_unpadded = gen_padded.rstrip(b'\x00')

vals = {
 'adj_verification':'KlcAG2cbAAsKSl1KVi0FGiJbDHMI',
 'android_uuid':'d773f47f-fc0e-4994-9cf7-7c3cf5bb6368','api_level':'31',
 'app_token':'jut9tib0eeps','app_version':'3.13.9',
 'created_at':'2026-09-12T21:15:11.762Z+0200','device_name':'moto g42',
 'device_type':'phone','environment':'production','google_play_instant':'0',
 'gps_adid':'f476b3d4-e0b1-4707-bc43-6153d17f7f8c','gps_adid_src':'service',
 'hardware_name':'S2SE32.28-28-4','installed_at':'2026-09-08T12:20:49.782Z+0200',
 'os_build':'S2SE32.28-28-4','os_name':'android','os_version':'12',
 'package_name':'com.penti.app','referrer':'utm_source=google-play&utm_medium=organic',
 'referrer_api':'google','adj_signing_id':'1500000','session_count':'1',
 'session_length':'0','source':'install_referrer','subsession_count':'1',
 'time_spent':'0','tracking_enabled':'1',
 'updated_at':'2026-09-10T07:26:18.015Z+0200','activity_kind':'click',
 'client_sdk':'android5.7.0','headers_id':'10','native_version':'5.0.0'}
padded, unpadded = M.claims_for_law(vals, 'click')
our_unpadded = padded.rstrip(b'\x00')

print('genuine padded   : %d B   (d7 unpadded = %d)' % (len(gen_padded), int(r8['d7'],16)))
print('our padded       : %d B   (unpadded %d)' % (len(padded), unpadded))
print()
print('UNPADDED IDENTICAL : %s' % (our_unpadded == gen_unpadded))
print('PADDED   IDENTICAL : %s' % (padded == gen_padded))
if our_unpadded != gen_unpadded:
    for i,(a,b) in enumerate(zip(our_unpadded, gen_unpadded)):
        if a != b:
            print('first diff at %d' % i)
            print('  ours   : %r' % our_unpadded[max(0,i-50):i+40])
            print('  genuine: %r' % gen_unpadded[max(0,i-50):i+40])
            break
    else:
        print('lens: ours %d genuine %d' % (len(our_unpadded), len(gen_unpadded)))
else:
    print()
    print('=> our click claim law is BYTE-EXACT vs the genuine row8 d10.')
    print('   padding differs only by %d NUL byte(s) (4-byte alignment).'
          % (len(padded) - len(gen_padded)))
