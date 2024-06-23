const assert = require("assert");
const {
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
} = require("./index");

// Run tests
(function runTests() {
  console.log("Running tests...");

  // Key generation test
  console.log("\n=== Key Generation Test ===");
  const { privateKey, publicKey } = generateKeyPair();
  assert(privateKey, "Private key should be generated");
  assert(publicKey, "Public key should be generated");
  console.log("Key pair generation test passed");

  // Private key to public key conversion test
  console.log("\n=== Private Key to Public Key Conversion Test ===");
  const derivedPublicKey = privateKeyToPublicKey(privateKey);
  assert(
    derivedPublicKey === publicKey,
    "Derived public key should match the generated public key"
  );
  console.log("Private key to public key conversion test passed");

  // Sign and verify message test
  console.log("\n=== Sign and Verify Message Test ===");
  const message = "Hello, world!";
  const signature = signMessage(privateKey, message);
  const isValidSignature = verifySignature(publicKey, message, signature);
  assert(isValidSignature, "Signature should be valid");
  console.log("Sign and verify message test passed");

  // Difficulty verification test
  console.log("\n=== Difficulty Verification Test ===");
  const hash = "0000abcdef";
  const difficulty = 4;
  const isDifficultyValid = difficultyverify(difficulty, hash);
  assert(isDifficultyValid, "Difficulty should be verified correctly");
  console.log("Difficulty verification test passed");

  // Hash message test
  console.log("\n=== Hash Message Test ===");
  const messageHash = hashMessage(message);
  assert(messageHash.length === 64, "Hash length should be 64 characters");
  console.log("Hash message test passed");

  // Encrypt and decrypt message test
  console.log("\n=== Encrypt and Decrypt Message Test ===");
  const encryptedMessage = encryptMessageWithPublicKey(message, publicKey);
  const decryptedMessage = decryptMessageWithPrivateKey(
    encryptedMessage,
    privateKey
  );
  assert(
    decryptedMessage === message,
    "Decrypted message should match the original message"
  );
  console.log("Encrypt and decrypt message test passed");

  // Post template creation test
  console.log("\n=== Post Template Creation Test ===");
  const postContent = "This is a test post.";
  const postHashtags = ["test", "post"];
  const postAttachments = [{ type: "image", url: "http://example.com/image.png" }];
  const post = postTemplate(postContent, postHashtags, postAttachments);
  assert(post.content === postContent, "Post content should match");
  assert.deepStrictEqual(post.hashtags, postHashtags, "Post hashtags should match");
  assert.deepStrictEqual(post.attachments, postAttachments, "Post attachments should match");
  console.log("Post template creation test passed");

  // Meta template creation test
  console.log("\n=== Meta Template Creation Test ===");
  const metaName = "Test User";
  const metaAbout = "This is a test user.";
  const metaImage = "http://example.com/image.png";
  const metaWebsite = "http://example.com";
  const metaFollowed = ["user1", "user2"];
  const metaHashtags = ["test", "user"];
  const meta = metaTemplate(
    metaName,
    metaAbout,
    metaImage,
    metaWebsite,
    metaFollowed,
    metaHashtags
  );
  assert(meta.name === metaName, "Meta name should match");
  assert(meta.about === metaAbout, "Meta about should match");
  assert(meta.image === metaImage, "Meta image should match");
  assert(meta.website === metaWebsite, "Meta website should match");
  assert.deepStrictEqual(meta.followed, metaFollowed, "Meta followed should match");
  assert.deepStrictEqual(meta.hashtags, metaHashtags, "Meta hashtags should match");
  console.log("Meta template creation test passed");

  // Create and verify commit test
  console.log("\n=== Create and Verify Commit Test ===");
  const postData = postTemplate("Hello, world!", [], []);
  const commitData = createCommit(privateKey, postData, "post", 4);
  console.log("Generated commit:", commitData);
  const isValidCommit = verifyCommit(commitData, 4);
  assert(isValidCommit, "Commit should be valid");
  console.log("Commit verification test passed");

  // Encrypt and decrypt private message test
  console.log("\n=== Encrypt and Decrypt Private Message Test ===");
  const privateMessage = "Hey love! How are you? I miss you!";
  const encodedMsg = encryptMessageWithPublicKey(privateMessage, derivedPublicKey);
  console.log("Encoded message:", encodedMsg);
  const decodedMsg = decryptMessageWithPrivateKey(encodedMsg, privateKey);
  console.log("Decoded message:", decodedMsg);
  assert(decodedMsg === privateMessage, "Decrypted message should match the original message");
  console.log("Encrypt and decrypt private message test passed");

  console.log("\nAll tests passed successfully!");

})();
