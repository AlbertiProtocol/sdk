const EthCrypto = require("eth-crypto");

/**
 * Creates a new identity.
 * @returns {Object} - The identity object containing private and public keys.
 */
function createIdentity() {
  const identity = EthCrypto.createIdentity();
  return identity;
}

/**
 * Converts a public key to an address.
 * @param {string} publicKey - The public key.
 * @returns {string} - The address.
 */
function publicKeyToAddress(publicKey) {
  return EthCrypto.publicKey.toAddress(publicKey);
}

/**
 * Converts a private key to a public key.
 * @param {string} privateKey - The private key.
 * @returns {string} - The public key.
 */
function privateKeyToPublicKey(privateKey) {
  return EthCrypto.publicKeyByPrivateKey(privateKey);
}

/**
 * Verifies if the hash meets the required difficulty.
 * @param {number} difficulty - The difficulty level.
 * @param {string} hash - The hash string.
 * @returns {boolean} - True if hash meets the difficulty, otherwise false.
 */
function difficultyverify(difficulty, hash) {
  return hash.startsWith("0x" + "0".repeat(difficulty));
}

/**
 * Hashes a message using keccak256.
 * @param {string} message - The message to hash.
 * @returns {string} - The hashed message.
 */
function hashMessage(message) {
  return EthCrypto.hash.keccak256(message);
}

/**
 * Signs a message with a given private key.
 * @param {string} privateKey - The private key.
 * @param {string} message - The message to sign.
 * @returns {string} - The message signature.
 */
function signMessage(privateKey, message) {
  return EthCrypto.sign(privateKey, hashMessage(message));
}

/**
 * Recovers the public key from a signature and message.
 * @param {string} signature - The signature.
 * @param {string} message - The message.
 * @returns {string} - The recovered public key.
 */
function recoverPublicKey(signature, message) {
  return EthCrypto.recoverPublicKey(signature, hashMessage(message));
}

/**
 * Encodes a message by encrypting it with the receiver's public key.
 * @param {string} message - The message to encode.
 * @param {string} senderPrivateKey - The sender's private key.
 * @param {string} receiverPublicKey - The receiver's public key.
 * @returns {Promise<Object>} - The encoded message object.
 */
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

/**
 * Decodes an encrypted message with the receiver's private key.
 * @param {string} encryptedString - The encrypted message string.
 * @param {string} receiverPrivateKey - The receiver's private key.
 * @returns {Promise<Object>} - The decoded message object.
 */
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

/**
 * Creates a post template.
 * @param {string} content - The content of the post.
 * @param {string[]} [hashtags=[]] - Array of hashtags.
 * @param {Object[]} [attachments=[]] - Array of attachments.
 * @param {string|null} [parentID=null] - ID of the parent post, if any.
 * @returns {Object} - The post template object.
 */
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

/**
 * Creates a meta template.
 * @param {string} name - Name of the user or entity.
 * @param {string} about - Description about the user or entity.
 * @param {string} image - URL of the profile image.
 * @param {string} website - URL of the website.
 * @param {string[]} [followed=[]] - Array of followed users or entities.
 * @param {string[]} [hashtags=[]] - Array of followed hashtags.
 * @param {Object[]} [bookmarks=[]] - Array of bookmarks.
 * @returns {Object} - The meta template object.
 */
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

/**
 * Creates a commit with a specific difficulty.
 * @param {string} privateKey - The private key to sign the commit.
 * @param {string} data -  MetaTemplate | PostTemplate | EncodedMessage;
 * @param {string} type - post | meta | message
 * @param {number} [difficulty=3] - The difficulty level.
 * @returns {Object} - The commit object.
 */
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

/**
 * Verifies a commit.
 * @param {Object} commit - The commit object.
 * @param {number} [difficulty=3] - The difficulty level.
 * @returns {boolean} - True if the commit is valid, otherwise false.
 */
function verifyCommit(commit, difficulty = 3) {
  if (!verifyObject(commit)) {
    return false;
  }

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

/**
 * Verifies if the data object contains the required properties.
 * @param {Object} dataObject - The data object to verify.
 * @returns {boolean} - True if the data object is valid, otherwise false.
 */

function verifyObject(dataObject) {
  if (Object.keys(dataObject).length !== 6) {
    return false;
  }

  if (checkdatastructure(dataObject.data, dataObject.type) === false) {
    return false;
  }

  if (
    dataObject.hasOwnProperty("commitAt") &&
    dataObject.hasOwnProperty("data") &&
    dataObject.hasOwnProperty("publicKey") &&
    dataObject.hasOwnProperty("signature") &&
    dataObject.hasOwnProperty("type") &&
    dataObject.hasOwnProperty("nonce")
  ) {
    return true;
  } else {
    return false;
  }
}

/**
 * Verifies the structure of the data object.
 * @param {Object} data - The data object to verify.
 * @param {string} type - post | meta | message
 * @returns {boolean} - True if the data object is valid, otherwise false.
 */

function checkdatastructure(data, type) {
  if ((type = "post")) {
    if (
      data.hasOwnProperty("parent") &&
      data.hasOwnProperty("content") &&
      data.hasOwnProperty("hashtags") &&
      data.hasOwnProperty("attachments")
    ) {
      if (data.hashtags.length > 0) {
        data.hashtags.forEach((element) => {
          if (typeof element !== "string") {
            return false;
          }

          if (element.length > 32) {
            return false;
          }

          if (!element.match(/^[a-zA-Z0-9]*$/)) {
            return false;
          }
        });
      }
      if (data.attachments.length > 0) {
        let allgood = false;
        let allgoodx = false;

        data.attachments.forEach((element) => {
          if (element.hasOwnProperty("type")) {
            allgood = true;
          }

          if (element.hasOwnProperty("cid")) {
            allgoodx = !allgoodx;
          }

          if (element.hasOwnProperty("url")) {
            allgoodx = !allgoodx;
          }
        });

        if (allgood === false || allgoodx === false) {
          return false;
        }
      }

      return true;
    } else {
      return false;
    }
  }

  if ((type = "meta")) {
    if (
      data.hasOwnProperty("followed") &&
      data.hasOwnProperty("hashtags") &&
      data.hasOwnProperty("bookmarks") &&
      data.hasOwnProperty("name") &&
      data.hasOwnProperty("about") &&
      data.hasOwnProperty("image") &&
      data.hasOwnProperty("website")
    ) {
      data.hashTags.forEach((element) => {
        if (typeof element !== "string") {
          return false;
        }

        if (element.length > 32) {
          return false;
        }

        if (!element.match(/^[a-zA-Z0-9]*$/)) {
          return false;
        }
      });

      return true;
    } else {
      return false;
    }
  }

  if ((type = "message")) {
    if (data.hasOwnProperty("receiver") && data.hasOwnProperty("message")) {
      return true;
    } else {
      return false;
    }
  }

  return false;
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
