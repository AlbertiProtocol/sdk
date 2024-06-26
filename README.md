# Alberti Protocol SDK

The Alberti Protocol SDK is a comprehensive toolkit for cryptographic operations, including message encryption, decryption, signing, verification, and identity management. applications.

### Installation

```
npm install @albertiprotocol/sdk
```
### Function Overview

#### Key Management

1. **generateKeyPair()**
   - Generates a new key pair (private and public key).
   - Example usage:
     ```javascript
     const { privateKey, publicKey } = generateKeyPair();
     ```

2. **privateKeyToPublicKey(privateKey)**
   - Converts a given private key to its corresponding public key.
   - Example usage:
     ```javascript
     const publicKey = privateKeyToPublicKey(privateKey);
     ```

#### Message Signing and Verification
3. **signMessage(privateKeyHex, message)**
   - Signs a message using the provided private key.
   - Example usage:
     ```javascript
     const signature = signMessage(privateKey, 'Hello, world!');
     ```

4. **verifySignature(publicKeyHex, message, signatureHex)**
   - Verifies a message against a signature using the provided public key.
   - Example usage:
     ```javascript
     const isValid = verifySignature(publicKey, 'Hello, world!', signature);
     ```

#### Message Encryption and Decryption
5. **encryptMessageWithPublicKey(message, recipientPublicKey)**
   - Encrypts a message using the recipient's public key.
   - Example usage:
     ```javascript
     const encryptedMessage = encryptMessageWithPublicKey('Hello, World!', publicKey);
     ```

6. **decryptMessageWithPrivateKey(encryptedMessage, recipientPrivateKey)**
   - Decrypts an encrypted message using the recipient's private key.
   - Example usage:
     ```javascript
     const decryptedMessage = decryptMessageWithPrivateKey(encryptedMessage, privateKey);
     ```

#### Hashing and Difficulty Verification
7. **hashMessage(message)**
   - Generates a SHA-256 hash of the given message.
   - Example usage:
     ```javascript
     const messageHash = hashMessage('Hello, world!');
     ```

8. **difficultyverify(difficulty, hash)**
   - Verifies that a given hash meets the specified difficulty criteria.
   - Example usage:
     ```javascript
     const isValid = difficultyverify(4, '0000abcdef');
     ```

#### Template Functions
9. **postTemplate(content, hashtags = [], attachments = [], parentID = null)**
   - Creates a template for a post with specified content, hashtags, attachments, and optional parent ID.
   - Example usage:
     ```javascript
     const post = postTemplate('This is a test post.', ['test', 'post'], [{ type: 'image', url: 'http://example.com/image.png' }]);
     ```

10. **metaTemplate(name, about, image, website, followed = [], hashtags = [])**
    - Creates a template for metadata with specified details such as name, about, image, website, followed users, and hashtags.
    - Example usage:
      ```javascript
      const meta = metaTemplate('Test User', 'This is a test user.', 'http://example.com/image.png', 'http://example.com', ['user1', 'user2'], ['test', 'user']);
      ```

#### Data Commit Creation and Verification
11. **createCommit(privateKey, data, type, difficulty = 3)**
    - Generates a commit object by signing a data payload and ensuring it meets the specified difficulty criteria.
    - Example usage:
      ```javascript
      const commit = createCommit(privateKey, postData, 'post', 4);
      ```

12. **verifyCommit(commit, difficulty = 3)**
    - Validates the structure, signature, and difficulty of a commit object.
    - Example usage:
      ```javascript
      const isValid = verifyCommit(commit, 4);
      ```

---

### Example Usage

#### Generate a Key Pair
```javascript
const { generateKeyPair } = require('./alberti-sdk');
const { privateKey, publicKey } = generateKeyPair();
console.log(`Private Key: ${privateKey}`);
console.log(`Public Key: ${publicKey}`);
```

#### Encrypt and Decrypt a Message
```javascript
const { encryptMessageWithPublicKey, decryptMessageWithPrivateKey } = require('./alberti-sdk');

// Encrypt message
const encryptedMessage = encryptMessageWithPublicKey('Hello, World!', publicKey);
console.log(`Encrypted Message: ${encryptedMessage.ciphertext}`);

// Decrypt message
const decryptedMessage = decryptMessageWithPrivateKey(encryptedMessage, privateKey);
console.log(`Decrypted Message: ${decryptedMessage}`);
```

#### Create and Verify a Commit
```javascript
const { createCommit, verifyCommit, postTemplate } = require('./alberti-sdk');

// Define post data
const postData = postTemplate('Hello, world!', [], []);

// Create commit
const commit = createCommit(privateKey, postData, 'post', 4);

// Verify commit
const isValid = verifyCommit(commit, 4);
console.log(`Is the commit valid? ${isValid}`);
```

---

### Running Tests

To ensure all functionalities are working correctly, we have a set of tests. Run these tests using the following command:

```javascript
node test.js
```

The tests include:
- Key generation and verification
- Message signing and signature verification
- Difficulty verification
- Message hashing
- Message encryption and decryption
- Template creation (post and meta)
- Commit creation and verification

---

### Contributing

We welcome contributions from the community. If you have any suggestions, bug reports, or improvements, please feel free to submit a pull request or open an issue.

---

Join us in building a more secure and private internet with Alberti, redefining privacy and security in the digital age.
