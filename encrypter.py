from caesars import *
import random
from baseconv import BaseConverter

base18 = BaseConverter('F260H1B34E89AC5D7G')

class Encrypter(object):
	def _map(self, iter, ap):
		ret = []
		for i in iter:
			ret.append(ap(i))
		return ret

	def _map_enumarated(self, iter, ap):
		ret = []
		for i, j in enumerate(iter):
			ret.append(ap(i, j))
		return ret
	
	def encrypt(self, s: str, prm_key: int, cae_key: int, joiner: str = '_', tb: int = 981328):
		cae_en_s = caesar(s, cae_key, ceasar_en)
		ord_en_cen = self._map(cae_en_s, ord)
		prm_en_ord = self._map_enumarated(ord_en_cen, lambda b, a: a + prm_key + b * tb)
		ocd_en_prm = self._map(prm_en_ord, base18.encode)
		jin_en_ocd = joiner.join(ocd_en_prm)
		return jin_en_ocd

	def decrypt(self, s: str, prm_key: int, cae_key: int, spliter: str = '_', tb: int = 981328):
		jin_de_ocd = s.split(spliter)
		ocd_de_prm = self._map(jin_de_ocd, base18.decode)
		prm_de_int = self._map(ocd_de_prm, int)
		int_de_ord = self._map_enumarated(prm_de_int, lambda b, a: a - prm_key - b * tb)
		ord_de_cen = self._map(int_de_ord, chr)
		cae_de_s = caesar(ord_de_cen, cae_key, ceasar_de)
		return ''.join(cae_de_s)
	
	def encrypt2(self, s: str, prm_key: int, cae_key: int, tb: int = 981328):
		_enc = self.encrypt(s, prm_key, cae_key, 'é', tb)
		prm = random.randint(100000, 999999)
		cae = random.randint(1, 28)
		tb0 = random.randint(100000, 999999)
		enc = self.encrypt(_enc, prm, cae, tb=tb0)
		return {
			'result': enc,
			'prm': prm,
			'cae': cae,
			'tb0': tb0,
			}
	
	def decrypt2(self, s: str, prm_key: int, cae_key: int, prm: int, cae: int, tb0: int, tb: int = 981328):
		_dec = self.decrypt(s, prm, cae, tb=tb0)
		dec = self.decrypt(_dec, prm_key, cae_key, 'é', tb)
		return dec

enc = Encrypter()
