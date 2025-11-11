'''
    *  Full Name: Luigi Rossi
    *  Course:EECS 3482 A
    *  Description:  This program securely stores, retrieves, and manages passwords for different domains 
       using cryptographic methods. It also secures and protects your passwords from attackers by using cryptography. It
       allows users to set new passwords, get existing ones, remove entries and dump/loadthe database securely.
    *
    *  FOR EDUCATION PURPOSES ONLY. PLEASE DO NOT DISTRIBUTE WIHTOUT PERMISSION!
'''
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import pickle


class Keychain:
    
    MAX_PW_LEN_BYTES = 64

    def __init__(self, password):

            # Validate
        if not password or not isinstance(password, str):
            err = 'No valid password'
            raise Exception(err)

        # Generate random salt (store in object, later also in dump)
        self.salt = get_random_bytes(16)

        # Derive keys with PBKDF2
        dk = PBKDF2(password.encode('utf-8'), self.salt, dkLen=64, count=100000, hmac_hash_module=SHA256)

        # Split into AES + HMAC keys
        self.aes_key = dk[:32]
        self.hmac_key = dk[32:]

        # Initialize empty key-value store
        self.kvs = {}

        

    def load(self, password=None, data=None, checksum=None):
        """ Loads a saved password manager.
        Args:
            password (string): master password (ASCII string)
            data (str): hex-encoded serialized representation
            checksum (str): optional hex-encoded checksum (for rollback protection)
        Raises:
            ValueError: malformed format or checksum mismatch        """

        if not password or not isinstance(password, str):
            raise ValueError("No valid password provided")
        if data is None:
            raise ValueError("No data provided to load")

        try:
            raw_data = bytes.fromhex(data)

            # Deserialize the pickled bytes
            deserialized = pickle.loads(raw_data)
            self.kvs = deserialized
        except Exception as e:
            raise ValueError("Malformed serialized format") from e

        # Extract the salt and actual kvs
        if isinstance(self.kvs, dict) and "salt" in self.kvs:
            self.salt = self.kvs["salt"]
            self.kvs = self.kvs.get("kvs", {})
        else:
            raise ValueError("Serialized data missing salt")

        # Re-derive keys
        dk = PBKDF2(password.encode("utf-8"),
                    self.salt,
                    dkLen=64,
                    count=100000,
                    hmac_hash_module=SHA256)
        self.aes_key = dk[:32]
        self.hmac_key = dk[32:]

        # Verify checksum
        if checksum is not None:
            computed_checksum = SHA256.new(raw_data).hexdigest()
            if computed_checksum != checksum:
                raise ValueError("Checksum mismatch — possible attack")

        print("Keychain loaded successfully!")

  

    def dump(self):
   # Package salt + KVS into one structure
        to_store = {
            "salt": self.salt,
            "kvs": self.kvs
        }

        # Serialize into bytes
        serialized = pickle.dumps(to_store)

        # Encode in hex
        data_hex = serialized.hex()

        # Compute checksum using SHA-256
        checksum = SHA256.new(serialized).hexdigest()

        # Return both values
        return data_hex, checksum

    

    def get(self, domain):
        """Return the decrypted password for a domain from the password manager."""

        if not isinstance(domain, str) or not domain:
            raise ValueError("Invalid domain name")

        # Compute HMAC(domain) to match how it was stored in set()
        domain_hmac = HMAC.new(self.hmac_key, domain.encode("utf-8"), digestmod=SHA256).hexdigest()

        # Check if the entry exists
        if domain_hmac not in self.kvs:
            return None  # domain not found

        try:
            # Decode the hex-encoded ciphertext
            encrypted_data = bytes.fromhex(self.kvs[domain_hmac])

            # Split into parts: nonce (16 bytes), ciphertext, tag (16 bytes)
            nonce = encrypted_data[:16]
            tag = encrypted_data[-16:]
            ciphertext = encrypted_data[16:-16]

            # Decrypt using AES-GCM
            cipher = AES.new(self.aes_key, AES.MODE_GCM, nonce=nonce)
            cipher.update(domain_hmac.encode("utf-8"))  # AAD must match what was used in set()
            decrypted_password = cipher.decrypt_and_verify(ciphertext, tag)

            # Convert bytes back to string
            return decrypted_password.decode("utf-8")

        except (ValueError, KeyError):
            # ValueError: authentication failed (wrong key or tampered data)
            # KeyError: domain not in KVS
            return None

    def set(self, domain, password):
        """Associates a password with a domain and adds it to the password manager."""

        # Validate inputs
        if not isinstance(password, str):
            raise ValueError("Password must be a string")
        if len(password.encode("utf-8")) > self.MAX_PW_LEN_BYTES:
            raise ValueError("Password length exceeds the maximum of 64 bytes")
        if not isinstance(domain, str) or not domain:
            raise ValueError("Invalid domain name")

        # Compute HMAC(domain) — this will be the secure key in the KVS
        domain_hmac = HMAC.new(self.hmac_key, domain.encode("utf-8"), digestmod=SHA256).hexdigest()

        # Encrypt the password using AES-GCM
        cipher = AES.new(self.aes_key, AES.MODE_GCM)
        cipher.update(domain_hmac.encode("utf-8"))  # AAD = domain HMAC
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(password.encode("utf-8"))

        # Combine all encrypted components
        encrypted_data = nonce + ciphertext + tag

        # Store in KVS
        self.kvs[domain_hmac] = encrypted_data.hex()

        # Confirmation for testing 
        print("Stored encrypted password for " + domain)


 

    def remove(self, domain):
        """Removes the password for the requested domain from the password manager.
        Args:
            domain (str): the domain to remove
        Returns:
            success (bool): True if the domain was removed, False if not found
        """

        # Validate domain
        if not isinstance(domain, str) or not domain:
            raise ValueError("Invalid domain name")

        # Compute the HMAC of the domain (to match how it was stored)
        domain_hmac = HMAC.new(self.hmac_key, domain.encode("utf-8"), digestmod=SHA256).hexdigest()

        # 3. Check if the entry exists
        if domain_hmac in self.kvs:
            del self.kvs[domain_hmac]
            print("Removed password for " + domain)
            return True

        # Domain not found
        print("No entry found for " + domain)
        return False


