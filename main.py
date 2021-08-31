from encrypter import enc
import chardet
from sys import argv, stderr; ewrite = stderr.write

# Regex for separating encoding from 
REG = r'.*: (?P<encoding>.*) with confidence (?P<confidence>\d*\.\d*)'

ARGS = argv

if len(ARGS) == 5:
	if ARGS[1] in ('e','enc','encrypt'):
		prm_key = int(ARGS[3])
		cae_key = int(ARGS[4])
		res = enc.encrypt(ARGS[2], prm_key, cae_key)
		ewrite('primary key: ' + str(prm_key) + '\n')
		ewrite('caesar key: ' + str(cae_key) + '\n')
		ewrite('result:\n')
		print(res)
	elif ARGS[1] in ('e2','enc2','encrypt2'):
		prm_key = int(ARGS[3])
		cae_key = int(ARGS[4])
		res = enc.encrypt2(ARGS[2], prm_key, cae_key)
		ewrite('primary key: ' + str(prm_key) + '\n')
		ewrite('caesar key: ' + str(cae_key) + '\n')
		ewrite('private primary key: ' + str(res['prm']) + '\n')
		ewrite('private caesar key: ' + str(res['cae']) + '\n')
		ewrite('tb: ' + str(res['tb0']) + '\n')
		ewrite('result:\n')
		print(res['result'])
	elif ARGS[1] in ('d','dec','decrypt'):
		prm_key = int(ARGS[3])
		cae_key = int(ARGS[4])
		res = enc.decrypt(ARGS[2], prm_key, cae_key)
		ewrite('primary key: ' + str(prm_key) + '\n')
		ewrite('caesar key: ' + str(cae_key) + '\n')
		ewrite('result:\n')
		print(res)
	elif ARGS[1] in ('ef','encf','encryptf'):
		with open(ARGS[2]) as f:
			fr = f.read()
		prm_key = int(ARGS[3])
		cae_key = int(ARGS[4])
		res = enc.encrypt(fr, prm_key, cae_key)
		ewrite('primary key: ' + str(prm_key) + '\n')
		ewrite('caesar key: ' + str(cae_key) + '\n')
		ewrite('result:\n')
		print(res)
	elif ARGS[1] in ('ef2','encf2','encryptf2'):
		with open(ARGS[2]) as f:
			fr = f.read()
		prm_key = int(ARGS[3])
		cae_key = int(ARGS[4])
		res = enc.encrypt2(fr, prm_key, cae_key)
		ewrite('primary key: ' + str(prm_key) + '\n')
		ewrite('caesar key: ' + str(cae_key) + '\n')
		ewrite('private primary key: ' + str(res['prm']) + '\n')
		ewrite('private caesar key: ' + str(res['cae']) + '\n')
		ewrite('tb: ' + str(res['tb0']) + '\n')
		ewrite('result:\n')
		print(res['result'])
	elif ARGS[1] in ('df','decf','decryptf'):
		encod = chardet.detect(open(ARGS[2], 'rb').read())['encoding']
		with open(ARGS[2], encoding=encod) as f:
			fr = f.read().strip()
		prm_key = int(ARGS[3])
		cae_key = int(ARGS[4])
		res = enc.decrypt(fr, prm_key, cae_key)
		ewrite('primary key: ' + str(prm_key) + '\n')
		ewrite('caesar key: ' + str(cae_key) + '\n')
		ewrite('result:\n')
		print(res)
elif len(ARGS) == 8:
	if ARGS[1] in ('d2','dec2','decrypt2'):
		prm_key = int(ARGS[3])
		cae_key = int(ARGS[4])
		prm = int(ARGS[5])
		cae = int(ARGS[6])
		tb0 = int(ARGS[7])
		res = enc.decrypt2(ARGS[2], prm_key, cae_key, prm, cae, tb0)
		ewrite('primary key: ' + str(prm_key) + '\n')
		ewrite('caesar key: ' + str(cae_key) + '\n')
		ewrite('private primary key: ' + str(prm) + '\n')
		ewrite('private caesar key: ' + str(cae) + '\n')
		ewrite('tb: ' + str(tb0) + '\n')
		ewrite('result:\n')
		print(res)
	elif ARGS[1] in ('df2','decf2','decryptf2'):
		encod = chardet.detect(open(ARGS[2], 'rb').read())['encoding']
		with open(ARGS[2], encoding=encod) as f:
			fr = f.read().strip()
		prm_key = int(ARGS[3])
		cae_key = int(ARGS[4])
		prm = int(ARGS[5])
		cae = int(ARGS[6])
		tb0 = int(ARGS[7])
		res = enc.decrypt2(fr, prm_key, cae_key, prm, cae, tb0)
		ewrite('primary key: ' + str(prm_key) + '\n')
		ewrite('caesar key: ' + str(cae_key) + '\n')
		ewrite('private primary key: ' + str(prm) + '\n')
		ewrite('private caesar key: ' + str(cae) + '\n')
		ewrite('tb: ' + str(tb0) + '\n')
		ewrite('result:\n')
		print(res)