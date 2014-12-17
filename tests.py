import unittest
from keyfor.key import Key, MasterKey, Cypher, CypherAES256, CypherAES256HMAC

class KeyforTest(unittest.TestCase):

    def test_cypher(self):
        cyphers = (Cypher, CypherAES256, CypherAES256HMAC)
        for CypherClass in cyphers:
            plaintext = "Hi, how are you?"
            password = "secret1"
            encryptor = CypherClass(password=password)
            iv, cyphertext = encryptor.encrypt(plaintext)
        
            self.assertIsNotNone(iv)
            self.assertIsNotNone(cyphertext)
        
            length = len(plaintext)
        
            decryptor = CypherClass(iv=iv, password=password)
            decrypted = decryptor.decrypt(cyphertext=cyphertext)[:length]
        
            self.assertEqual(plaintext, decrypted)
        
    def test_encdec_key(self):
        key = Key(label='label', username='username', password='password')
        masterkey = MasterKey(password='secret1')
        enc = masterkey.encrypt_key(key=key)
        dec = masterkey.decrypt_key(enc)
        self.assertEqual(key, dec)

    def test_verify(self):
        key = Key(label='label', username='username', password='password')
        masterkey = MasterKey(password='secret1')
        enc = masterkey.encrypt_key(key=key)
        self.assertTrue(masterkey.verify(encrypted=enc))
        
if __name__ == '__main__':
    unittest.main()        