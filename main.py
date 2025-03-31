import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Import Kyber512 from kyber-py: a pure Python implementation of the ML-KEM/CRYSTALS-Kyber post-quantum algorithm.
from kyber_py.kyber import Kyber512

# === Simplified symmetric ratchet (Double Ratchet, symmetric part only) ===
#
# In the Double Ratchet Algorithm, every message is encrypted with a unique message key.
# A KDF chain (Key Derivation Function chain) is used to update a chain key and derive a fresh message key.
#
# Here we use HKDF (HMAC-based Key Derivation Function) with SHA-256 as the KDF.
# HKDF is a standard method to derive cryptographic keys from a shared secret.
#
# AESGCM (Advanced Encryption Standard in Galois/Counter Mode) is used as the AEAD (Authenticated Encryption with Associated Data)
# cipher. It provides both confidentiality and integrity for each message.
#
def ratchet_step(chain_key):
    """
    Advances the chain key and derives a new message key using HKDF.
    
    HKDF (HMAC-based Key Derivation Function) uses a cryptographic hash function (SHA-256 in our case)
    and a secret (here the current chain key) to produce new key material. It outputs a concatenated value
    that we split into a new chain key and a message key.
    
    Returns:
        new_chain_key (32 bytes), message_key (32 bytes)
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),  # Using SHA-256 hash function.
        length=64,                  # We derive 64 bytes: 32 for the new chain key, 32 for the message key.
        salt=None,                  # In a production system, use a salt for extra randomness.
        info=b"DoubleRatchet symmetric step"  # Contextual information.
    )
    out = hkdf.derive(chain_key)
    return out[:32], out[32:]

def derive_nonce(counter):
    """
    Derives a 12-byte nonce from the message counter.
    
    Nonce: A number used once. For AESGCM, a nonce must be unique for each encryption with the same key.
    Here we convert the counter to a 12-byte big-endian representation.
    """
    return counter.to_bytes(12, byteorder='big')

class DoubleRatchetState:
    """
    A simplified symmetric-key ratchet state.
    
    In the Double Ratchet, each message sent advances the sending chain key (and derives a new message key)
    while the receiving chain key is similarly updated upon receiving messages.
    This implementation only models the symmetric-key ratchet (i.e., key updating via a KDF chain),
    and does not implement the full DH ratchet (which would involve Diffie–Hellman updates).
    """
    def __init__(self, initial_chain_key):
        self.chain_key = initial_chain_key  # The current chain key.
        self.counter = 0  # Message counter, used to derive unique nonces.
    
    def send_message(self, plaintext, associated_data=b""):
        """
        Encrypts a plaintext message.
        
        The chain key is updated using ratchet_step to derive a new message key.
        The message key is then used with AESGCM to encrypt the plaintext.
        
        Returns:
            header (4-byte message counter), ciphertext (encrypted message).
        """
        self.chain_key, message_key = ratchet_step(self.chain_key)
        self.counter += 1
        nonce = derive_nonce(self.counter)
        aesgcm = AESGCM(message_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), associated_data)
        header = self.counter.to_bytes(4, byteorder='big')
        return header, ciphertext

    def receive_message(self, header, ciphertext, associated_data=b""):
        """
        Decrypts an incoming ciphertext.
        
        The header contains the sender's message number.
        This function advances the chain key until the internal counter matches the received counter,
        then uses the corresponding message key to decrypt the ciphertext.
        
        Returns:
            Decrypted plaintext string.
        """
        received_counter = int.from_bytes(header, byteorder='big')
        message_key = None
        while self.counter < received_counter:
            self.chain_key, message_key = ratchet_step(self.chain_key)
            self.counter += 1
        nonce = derive_nonce(self.counter)
        aesgcm = AESGCM(message_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
        return plaintext.decode()

# === Actor Class ===
#
# The Actor class represents a participant (e.g., Bob or Alice) in the communication.
# Each actor generates its own classical key pair (X25519) and post-quantum key pair (Kyber512).
# They use these to compute a hybrid shared session key that seeds the Double Ratchet state.
#
class Actor:
    def __init__(self, name):
        self.name = name
        # Generate classical Diffie–Hellman key pair using X25519.
        self.x_private = X25519PrivateKey.generate()
        self.x_public = self.x_private.public_key()
        # Generate post-quantum key pair using Kyber512.
        self.kyber_pk, self.kyber_sk = Kyber512.keygen()
        # These attributes will be set when a conversation starts.
        self.session_key = None
        self.dr_state = None

    def get_public_info(self):
        """
        Returns public information as a tuple:
            (X25519 public key, Kyber public key)
        This is used to exchange necessary data for establishing a shared session key.
        """
        return (self.x_public, self.kyber_pk)

    def start_conversation(self, peer_public_info):
        """
        Initiates a conversation with a peer.
        
        Uses the peer's public info (peer_x_public, peer_kyber_pk) to:
            - Compute the classical shared secret using X25519.
            - Encapsulate a Kyber shared secret using the peer's Kyber public key.
            - Combine both secrets using HKDF (HMAC-based Key Derivation Function) to derive a hybrid session key.
        Initializes the Double Ratchet state with the session key.
        
        Returns:
            Initiation data (Kyber ciphertext) for the peer.
        """
        peer_x_public, peer_kyber_pk = peer_public_info
        classical_ss = self.x_private.exchange(peer_x_public)
        kyber_shared_key, kyber_ct = Kyber512.encaps(peer_kyber_pk)
        if not isinstance(kyber_ct, bytes):
            kyber_ct = b"".join(kyber_ct)
        if len(kyber_ct) != 768:
            raise ValueError(f"Expected ciphertext length 768, got {len(kyber_ct)}")
        combined_ss = classical_ss + kyber_shared_key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"Hybrid PQXDH demo"
        )
        session_key = hkdf.derive(combined_ss)
        self.session_key = session_key
        self.dr_state = DoubleRatchetState(session_key)
        print(f"\n{self.name} starts conversation with session key: {session_key.hex()}")
        return {'kyber_ciphertext': kyber_ct}

    def complete_conversation(self, peer_public_info, initiation_data):
        """
        Completes the conversation as the responder.
        
        Given the peer's public info and the initiation data (Kyber ciphertext) from the initiator,
        this method computes the classical and post-quantum shared secrets, derives the hybrid session key,
        and initializes the Double Ratchet state.
        
        Returns:
            The hybrid session key.
        """
        peer_x_public, _ = peer_public_info
        kyber_ct = initiation_data['kyber_ciphertext']
        classical_ss = self.x_private.exchange(peer_x_public)
        kyber_shared_key = Kyber512.decaps(self.kyber_sk, kyber_ct)
        combined_ss = classical_ss + kyber_shared_key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"Hybrid PQXDH demo"
        )
        session_key = hkdf.derive(combined_ss)
        self.session_key = session_key
        self.dr_state = DoubleRatchetState(session_key)
        print(f"\n{self.name} completes conversation with session key: {session_key.hex()}")
        return session_key

    def send(self, plaintext, associated_data=b""):
        """
        Encrypts a message using the current Double Ratchet state.
        
        Advances the ratchet, encrypts the message using AESGCM (with the derived message key),
        prints the header and ciphertext, and returns them as a package.
        """
        if self.dr_state is None:
            raise ValueError("Conversation not started.")
        header, ciphertext = self.dr_state.send_message(plaintext, associated_data)
        print(f"\n{self.name} sends:")
        print("Header:", header.hex())
        print("Ciphertext:", ciphertext.hex())
        return (header, ciphertext)

    def receive(self, message_package, associated_data=b""):
        """
        Decrypts an incoming message package.
        
        Advances the ratchet until the message counter in the header is reached,
        decrypts the ciphertext using the corresponding message key, prints, and returns the plaintext.
        """
        if self.dr_state is None:
            raise ValueError("Conversation not started.")
        header, ciphertext = message_package
        plaintext = self.dr_state.receive_message(header, ciphertext, associated_data)
        print(f"\n{self.name} receives:")
        print("Decrypted message:", plaintext)
        return plaintext

# === Simulate a Conversation between Bob and Alice ===

# Instantiate actors.
bob = Actor("Bob")
alice = Actor("Alice")

# Exchange public information.
bob_public = bob.get_public_info()      # (Bob's X25519 public key, Bob's Kyber public key)
alice_public = alice.get_public_info()    # (Alice's X25519 public key, Alice's Kyber public key)

# Bob initiates the conversation.
initiation_data = bob.start_conversation(alice_public)
# Alice completes the conversation using Bob's initiation data.
alice.complete_conversation(bob_public, initiation_data)

# Now both have the same session key and initialized symmetric ratchet state.
# Bob sends his message.
message_from_bob = bob.send("I know who killed JFK")
alice.receive(message_from_bob)

# Alice replies with "who?".
message_from_alice = alice.send("who?")
bob.receive(message_from_alice)

# Bob follows up with his response.
message_from_bob_followup = bob.send("...................... your mom")
alice.receive(message_from_bob_followup)

