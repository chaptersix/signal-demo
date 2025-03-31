# signal-demo

**signal-demo** is a demonstration of a hybrid key exchange and a simplified Double Ratchet protocol inspired by Signal’s secure messaging architecture. In this demo, two actors (Bob and Alice) generate their own key pairs using both classical (X25519) and post‑quantum (Kyber512) cryptographic primitives. They then derive a shared session key via an HKDF (HMAC-based Key Derivation Function) that combines the classical and post‑quantum shared secrets. Finally, the shared session key seeds a simplified symmetric Double Ratchet that evolves the key for each message sent, ensuring that each message is encrypted with a unique message key.

> **Important:**  
> This demo is an educational prototype. It is a toy implementation and does not include the full complexity (or security) of a production‑ready Signal Double Ratchet protocol. It is not intended for cryptographic applications.

---

## Features

- **Hybrid Key Agreement:**  
  Combines classical Diffie–Hellman (X25519) and post‑quantum key encapsulation (Kyber512) to generate a shared session key.

- **Key Derivation with HKDF:**  
  Uses HKDF (HMAC-based Key Derivation Function) with SHA‑256 to derive cryptographically strong keys from the shared secret.

- **Simplified Double Ratchet:**  
  Implements a basic symmetric-key ratchet that updates a chain key using HKDF, and derives a unique message key for each message.

- **Actor-based Messaging:**  
  Encapsulates the protocol in an `Actor` class, which automatically generates key pairs and manages conversation initiation, message encryption (send), and decryption (receive).

---
## Installation

1. **Clone the repository (if applicable):**

   ```bash
   git clone https://github.com/chaptersix/signal-demo.git
   cd signal-demo
   ```


---

## Usage

Run the demo script using Python:

```bash
uv run  main.py
```

The script will simulate the following:
- Key generation for both Bob and Alice.
- Bob initiating a conversation with his public information.
- Alice completing the conversation initiation.
Output is printed to the console, including:
- The shared secrets.
- The derived hybrid session key.
- Message headers and ciphertexts.
- Decrypted messages.

---

## Code Structure

- **Hybrid Key Agreement:**  
  Combines X25519 and Kyber512 to derive a 32-byte session key.
  
- **Simplified Double Ratchet:**  
  - `ratchet_step(chain_key)`: Advances a chain key and derives a new message key via HKDF.
  - `DoubleRatchetState`: Maintains a symmetric ratchet state, updating a counter and chain key for each message.
  
- **Actor Class:**  
  Represents a conversation participant. It:
  - Generates its own X25519 and Kyber512 key pairs.
  - Provides `get_public_info()` for public key exchange.
  - Implements `start_conversation()` for initiating a session.
  - Implements `complete_conversation()` for responding to an initiation.
  - Provides `send()` and `receive()` methods to simulate message exchange.

---

## Acronyms Explained

- **HKDF (HMAC-based Key Derivation Function):**  
  A method to derive cryptographic keys from a shared secret using HMAC (Hash-based Message Authentication Code) with a secure hash function (SHA‑256).

- **X25519:**  
  A Diffie–Hellman key exchange algorithm based on Curve25519. It is used to establish a classical shared secret.

- **Kyber512:**  
  A post‑quantum Key Encapsulation Mechanism (KEM) based on lattice cryptography (CRYSTALS‑Kyber). It is used to provide post‑quantum security.

- **AESGCM (AES in Galois/Counter Mode):**  
  An AEAD (Authenticated Encryption with Associated Data) cipher that provides both confidentiality and data integrity.

- **AEAD:**  
  Authenticated Encryption with Associated Data. Encryption that provides both confidentiality and integrity for both encrypted data and additional non-encrypted data.

- **DH (Diffie–Hellman):**  
  A method for two parties to securely establish a shared secret over an insecure channel.

- **KDF (Key Derivation Function):**  
  A function used to derive one or more cryptographic keys from a secret value, such as a shared secret.

---
## Acknowledgments

- The design of this demo is inspired by Signal’s Double Ratchet Algorithm as documented in the [Signal Double Ratchet PDF (Revision 1, 2016-11-20)](https://signal.org/docs/specifications/doubleratchet/).
- The hybrid key agreement approach combines classical X25519 and post‑quantum Kyber512 as seen in modern PQ enhancements (e.g., Signal's PQXDH upgrade).

---

Enjoy exploring **signal-demo**!
