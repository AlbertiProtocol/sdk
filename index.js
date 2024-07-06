const CryptoJS = require("crypto-js");
const EC = require("elliptic").ec;
const curve = new EC("p521");

// Function to generate a new key pair with compressed public key
function generateKeyPair() {
  const keyPair = curve.genKeyPair();
  const privateKey = keyPair.getPrivate("hex");
  const publicKey = keyPair.getPublic(true, "hex"); // true for compressed
  return { privateKey, publicKey };
}

// Function to convert private key to public key
function privateKeyToPublicKey(privateKey) {
  const keyPair = curve.keyFromPrivate(privateKey, "hex");
  return keyPair.getPublic(true, "hex"); // true for compressed
}

// Function to sign a message
function signMessage(privateKeyHex, message) {
  const privateKey = curve.keyFromPrivate(privateKeyHex, "hex");
  const messageBuffer = Buffer.from(message, "utf-8");
  const signature = privateKey.sign(messageBuffer);
  return signature.toDER("hex");
}

// Function to verify a message against a signature
function verifySignature(publicKeyHex, message, signatureHex) {
  const publicKey = curve.keyFromPublic(publicKeyHex, "hex");
  const messageBuffer = Buffer.from(message, "utf-8");
  const signature = Buffer.from(signatureHex, "hex");
  return publicKey.verify(messageBuffer, signature);
}

// Function to verify difficulty
function difficultyverify(difficulty, hash) {
  return hash.startsWith("0".repeat(difficulty));
}

// Function to hash a message
function hashMessage(message) {
  return CryptoJS.SHA256(message).toString(CryptoJS.enc.Hex);
}

// Function to encrypt a message with a public key
function encryptMessageWithPublicKey(message, recipientPublicKey) {
  const recipientKey = curve.keyFromPublic(recipientPublicKey, "hex");
  const ephemeralKey = curve.genKeyPair();
  const sharedSecret = ephemeralKey.derive(recipientKey.getPublic());
  const sharedKey = CryptoJS.SHA256(sharedSecret.toString(16)).toString();
  const ciphertext = CryptoJS.AES.encrypt(message, sharedKey).toString();
  const ephemeralPublicKey = ephemeralKey.getPublic("hex");
  return { ciphertext, ephemeralPublicKey, recipientPublicKey };
}

// Function to decrypt a message with a private key
function decryptMessageWithPrivateKey(encryptedMessage, recipientPrivateKey) {
  const { ciphertext, ephemeralPublicKey } = encryptedMessage;
  const recipientKey = curve.keyFromPrivate(recipientPrivateKey, "hex");
  const ephemeralKey = curve.keyFromPublic(ephemeralPublicKey, "hex");
  const sharedSecret = recipientKey.derive(ephemeralKey.getPublic());
  const sharedKey = CryptoJS.SHA256(sharedSecret.toString(16)).toString();
  const bytes = CryptoJS.AES.decrypt(ciphertext, sharedKey);
  return bytes.toString(CryptoJS.enc.Utf8);
}

function postTemplate(content, hashtags = [], attachments = [], tags = [], parentID = null) {
  return {
    content: content,
    parent: parentID,
    hashtags: hashtags,
    attachments: attachments,
    tags: tags
  };
}

function metaTemplate(
  name,
  about,
  image,
  website,
  followed = [],
  hashtags = [],
) {
  return {
    followed,
    hashtags,
    name,
    about,
    image,
    website,
  };
}

function createCommit(privateKey, data, type, difficulty = 3) {
  try {
    let nonce = 0;
    let messageHash;

    do {
      nonce++;
      messageHash = hashMessage(`${JSON.stringify(data)}${nonce}`);
    } while (
      !difficultyverify(difficulty, messageHash) ||
      messageHash === undefined
    );

    const signature = signMessage(privateKey, messageHash);
    const publicKey = privateKeyToPublicKey(privateKey);

    return { data, type, nonce, publicKey, signature };
  } catch (error) {
    console.error("Error creating commit:", error);
    throw new Error("Failed to create commit.");
  }
}

function verifyCommit(commit, difficulty = 3) {
  if (!verifyObject(commit)) {
    return false;
  }

  const { data, nonce, publicKey, signature } = commit;
  const messageHash = hashMessage(`${JSON.stringify(data)}${nonce}`);
  const isValidSignature = verifySignature(publicKey, messageHash, signature);
  const isValidDifficulty = difficultyverify(difficulty, messageHash);
  return isValidSignature && isValidDifficulty;
}

function verifyObject(dataObject) {
  const requiredProperties = [
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

function checkDataStructure(data, type) {

  if (type === "post") {
    return (
      data.hasOwnProperty("parent") &&
      data.hasOwnProperty("content") &&
      data.hasOwnProperty("hashtags") &&
      data.hasOwnProperty("attachments") &&
      data.hasOwnProperty("tags") &&
      data.hashtags.every(
        (element) =>
          typeof element === "string" &&
          element.length <= 32 &&
          /^[a-zA-Z0-9]*$/.test(element),
      ) &&
      data.attachments.every(
        (element) =>
          element.hasOwnProperty("type") &&
          (element.type === "image" ||
            element.type === "video" ||
            element.type === "other") &&
          (element.hasOwnProperty("cid") || element.hasOwnProperty("url")),
      ) &&
      data.tags.every(
        (tag) =>
          tag.hasOwnProperty("key") &&
          tag.hasOwnProperty("value") &&
          typeof tag.key === "string" &&
          typeof tag.value === "string"
      )
    );
  }

  if (type === "meta") {
    return (
      data.hasOwnProperty("followed") &&
      data.hasOwnProperty("hashtags") &&
      data.hasOwnProperty("name") &&
      data.hasOwnProperty("about") &&
      data.hasOwnProperty("image") &&
      data.hasOwnProperty("website") &&
      data.hashtags.every(
        (element) =>
          typeof element === "string" &&
          element.length <= 32 &&
          /^[a-zA-Z0-9]*$/.test(element),
      )
    );
  }

  if (type === "message") {
    return data.hasOwnProperty("receiver") && data.hasOwnProperty("message");
  }

  return false;
}

module.exports = {
  generateKeyPair,
  privateKeyToPublicKey,
  signMessage,
  verifySignature,
  difficultyverify,
  hashMessage,
  encryptMessageWithPublicKey,
  decryptMessageWithPrivateKey,
  postTemplate,
  metaTemplate,
  createCommit,
  verifyCommit,
};
