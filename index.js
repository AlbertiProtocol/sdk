const EthCrypto = require("eth-crypto");

function difficultyverify(difficulty, hash) {
  return hash.startsWith("0x" + "0".repeat(difficulty));
}

function hashMessage(message) {
  return EthCrypto.hash.keccak256(message);
}

function signMessage(privateKey, message) {
  return EthCrypto.sign(privateKey, hashMessage(message));
}

function recoverPublicKey(signature, message) {
  return EthCrypto.recoverPublicKey(signature, hashMessage(message));
}

async function encodeMessage(message, senderPrivateKey, receiverPublicKey) {
  try {
    const signature = signMessage(senderPrivateKey, message);
    const encryptedMessage = await EthCrypto.encryptWithPublicKey(
      receiverPublicKey,
      JSON.stringify({ message, signature })
    );
    const encryptedString = EthCrypto.cipher.stringify(encryptedMessage);

    return {
      receiver: receiverPublicKey,
      message: encryptedString,
    };
  } catch (error) {
    console.error("Error encoding message:", error);
    throw new Error("Failed to encode message.");
  }
}

async function decodeMessage(encryptedString, receiverPrivateKey) {
  try {
    const encryptedObject = EthCrypto.cipher.parse(encryptedString);
    const decrypted = await EthCrypto.decryptWithPrivateKey(
      receiverPrivateKey,
      encryptedObject
    );
    const decryptedPayload = JSON.parse(decrypted);

    const senderAddress = recoverPublicKey(
      decryptedPayload.signature,
      decryptedPayload.message
    );

    return {
      sender: senderAddress,
      receiver: EthCrypto.publicKeyByPrivateKey(receiverPrivateKey),
      message: decryptedPayload.message,
    };
  } catch (error) {
    console.error("Error decoding message:", error);
    throw new Error("Failed to decode message.");
  }
}

function postTemplate(
  content,
  hashtags = [],
  attachments = [],
  parentID = null
) {
  return {
    parent: parentID,
    content,
    hashtags: hashtags,
    attachments: attachments,
  };
}

function metaTemplate(
  name,
  about,
  image,
  website,
  followed = [],
  hashtags = [],
  bookmarks = []
) {
  return {
    followed,
    hashtags,
    bookmarks,
    name,
    about,
    image,
    website,
  };
}

function createCommit(privateKey, data, type, difficulty = 3) {
  try {
    const commitAt = new Date().toISOString();
    let nonce = 0;
    let messageHash;
    let hashString;

    do {
      nonce++;
      hashString = `${data}${commitAt}${nonce}`;
      messageHash = hashMessage(hashString);
    } while (
      !difficultyverify(difficulty, messageHash) ||
      messageHash === undefined
    );

    const signature = signMessage(privateKey, messageHash);
    const publicKey = EthCrypto.publicKeyByPrivateKey(privateKey);

    return { commitAt, data, publicKey, signature, type, nonce };
  } catch (error) {
    console.error("Error creating commit:", error);
    throw new Error("Failed to create commit.");
  }
}

function verifyCommit(commit, difficulty = 3) {
  try {
    const hashString = `${commit.data}${commit.commitAt}${commit.nonce}`;
    const hashedData = hashMessage(hashString);

    if (!difficultyverify(difficulty, hashedData)) {
      console.log("Commit does not meet difficulty requirements.");
      return false;
    }

    const signer = recoverPublicKey(commit.signature, hashedData);
    return signer === commit.publicKey;
  } catch (error) {
    console.error("Error verifying commit:", error);
    return false;
  }
}

function createIdentity() {
  const identity = EthCrypto.createIdentity();
  return identity;
}

function publicKeyToAddress(publicKey) {
  return EthCrypto.publicKey.toAddress(publicKey);
}

function privateKeyToPublicKey(privateKey) {
  return EthCrypto.publicKeyByPrivateKey(privateKey);
}

module.exports = {
  createIdentity,
  createCommit,
  verifyCommit,
  publicKeyToAddress,
  privateKeyToPublicKey,
  postTemplate,
  metaTemplate,
  encodeMessage,
  decodeMessage,
};
