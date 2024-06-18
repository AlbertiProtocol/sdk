# Alberti Protocol SDK

The Alberti Protocol SDK is a comprehensive toolkit for cryptographic operations, including message encryption, decryption, signing, verification, and identity management. applications.

### Installation

```
npm install @albertiprotocol/sdk
```

### Rules

1. All media should be shared via IPFS
2. Client must store everything on the device
3. Pools are temporary place, for exchange of information

### Commit

A commit is the standardised signed packet of data, ready to be relayed to others.

```js
const { postTemplate, createCommit } = require("@albertiprotocol/sdk");

const privateKey = "your-private-key";
const difficulty = 4;

const post_content = "Bitcoin Price is $35,270";
const post_tags = ["bitcoin", "cryptocurrency", "fintech"];

const attachments = [
  { type: "img", cid: "QmXpYFUKcLik57tYeL5ccw5Acc4pvo8sVXZhf8oAAnQTUQ" },
  { type: "img", url: "https://i.ibb.co/q9V5S1Q/graph-1.png" },
];

const postdata = postTemplate(post_content, post_tags, attachments);

const commitdata = createCommit(privateKey, postdata, "post", difficulty);

// Now post commitdata to any pool
```
