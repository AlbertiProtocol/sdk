const elliptic = require("elliptic");
const CryptoJS = require("crypto-js");

const ec = new elliptic.ec("p521");

/**
 * Creates a new identity.
 * @returns {Object} - The identity object containing private and public keys.
 */
function createIdentity() {
  const keyPair = ec.genKeyPair();
  const privateKey = keyPair.getPrivate("hex");
  const publicKey = keyPair.getPublic("hex");
  return { privateKey, publicKey };
}

/**
 * Converts a private key to a public key.
 * @param {string} privateKey - The private key.
 * @returns {string} - The public key.
 */
function privateKeyToPublicKey(privateKey) {
  const keyPair = ec.keyFromPrivate(privateKey);
  return keyPair.getPublic("hex");
}

/**
 * Verifies if the hash meets the required difficulty.
 * @param {number} difficulty - The difficulty level.
 * @param {string} hash - The hash string.
 * @returns {boolean} - True if hash meets the difficulty, otherwise false.
 */
function difficultyverify(difficulty, hash) {
  return hash.startsWith("0".repeat(difficulty));
}

/**
 * Hashes a message using SHA-256.
 * @param {string} message - The message to hash.
 * @returns {string} - The hashed message.
 */
function hashMessage(message) {
  return CryptoJS.SHA256(message).toString(CryptoJS.enc.Hex);
}

/**
 * Signs a message with a given private key.
 * @param {string} privateKey - The private key.
 * @param {string} message - The message to sign.
 * @returns {string} - The message signature.
 */
function signMessage(privateKey, message) {
  const keyPair = ec.keyFromPrivate(privateKey);
  const msgHash = hashMessage(message);
  const signature = keyPair.sign(msgHash);
  return signature.toDER("hex");
}

/**
 * Recovers the public key from a signature and message.
 * @param {string} signature - The signature.
 * @param {string} message - The message.
 * @returns {string} - The recovered public key.
 */
function recoverPublicKey(signature, message) {
  const msgHash = hashMessage(message);
  const sig = elliptic.ec.Signature.fromDER(Buffer.from(signature, "hex"));
  const recKey = ec.recoverPubKey(
    Buffer.from(msgHash, "hex"),
    sig,
    sig.recoveryParam
  );
  return recKey.encode("hex");
}

/**
 * Encodes a message by encrypting it with a symmetric key.
 * @param {string} message - The message to encode.
 * @param {string} key - The encryption key.
 * @returns {string} - The encoded message string.
 */
function encodeMessage(message, key) {
  return CryptoJS.AES.encrypt(message, key).toString();
}

/**
 * Decodes an encrypted message with a symmetric key.
 * @param {string} encryptedString - The encrypted message string.
 * @param {string} key - The decryption key.
 * @returns {string} - The decoded message.
 */
function decodeMessage(encryptedString, key) {
  const bytes = CryptoJS.AES.decrypt(encryptedString, key);
  return bytes.toString(CryptoJS.enc.Utf8);
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
 * @param {string} data - MetaTemplate | PostTemplate | EncodedMessage;
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
    const publicKey = privateKeyToPublicKey(privateKey);

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
  const requiredProperties = [
    "commitAt",
    "data",
    "publicKey",
    "signature",
    "type",
    "nonce",
  ];

  for (const prop of requiredProperties) {
    if (!dataObject.hasOwnProperty(prop)) {
      return false;
    }
  }

  return checkDataStructure(dataObject.data, dataObject.type);
}

/**
 * Verifies the structure of the data object.
 * @param {Object} data - The data object to verify.
 * @param {string} type - post | meta | message
 * @returns {boolean} - True if the data object is valid, otherwise false.
 */
function checkDataStructure(data, type) {
  if (type === "post") {
    return (
      data.hasOwnProperty("parent") &&
      data.hasOwnProperty("content") &&
      data.hasOwnProperty("hashtags") &&
      data.hasOwnProperty("attachments") &&
      data.hashtags.every(
        (element) =>
          typeof element === "string" &&
          element.length <= 32 &&
          /^[a-zA-Z0-9]*$/.test(element)
      ) &&
      data.attachments.every(
        (element) =>
          element.hasOwnProperty("type") &&
          (element.type === "image" ||
            element.type === "video" ||
            element.type === "others") &&
          (element.hasOwnProperty("cid") || element.hasOwnProperty("url"))
      )
    );
  }

  if (type === "meta") {
    return (
      data.hasOwnProperty("followed") &&
      data.hasOwnProperty("hashtags") &&
      data.hasOwnProperty("bookmarks") &&
      data.hasOwnProperty("name") &&
      data.hasOwnProperty("about") &&
      data.hasOwnProperty("image") &&
      data.hasOwnProperty("website") &&
      data.hashtags.every(
        (element) =>
          typeof element === "string" &&
          element.length <= 32 &&
          /^[a-zA-Z0-9]*$/.test(element)
      )
    );
  }

  if (type === "message") {
    return data.hasOwnProperty("receiver") && data.hasOwnProperty("message");
  }

  return false;
}

module.exports = {
  createIdentity,
  createCommit,
  verifyCommit,
  privateKeyToPublicKey,
  postTemplate,
  metaTemplate,
  encodeMessage,
  decodeMessage,
};
