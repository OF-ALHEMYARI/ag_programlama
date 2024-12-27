const socket = io();
const messageContainer = document.getElementById("messageContainer");
const messageInput = document.getElementById("messageInput");
const messageType = document.getElementById("messageType");
const recipient = document.getElementById("recipient");
const sendBtn = document.getElementById("sendBtn");
const logoutBtn = document.getElementById("logoutBtn");

const peerPublicKeys = {};
const sharedSecretKeys = {};

messageType.addEventListener("change", () => {
  recipient.style.display = messageType.value === "private" ? "block" : "none";
});

window.onload = async () => {
  await generateKey();
  socket.emit("public_key", { publicKey: window.publicKeyBase64 });
};

socket.on("connect", () => {
  appendMessage("System", "Connected to server", "system");
});

socket.on("system_message", (data) => {
  appendMessage("System", data.message, "system");
});

socket.on("message", async (data) => {
  await generateKey();
  if (data.sender === localStorage.getItem("username")) {
    return;
  }
  if (data.encrypted && (sharedSecretKeys[data.sender] || data.publicKey)) {
    if (!sharedSecretKeys[data.sender] && data.publicKey) {
      peerPublicKeys[data.sender] = data.publicKey;
      sharedKey = await deriveSharedKey(window.privateKey, data.publicKey);
      sharedSecretKeys[data.sender] = sharedKey;
    }
    try {
      // Detailed logging for debugging
      console.log("Decryption Attempt Details:", {
        sender: data.sender,
        keyAvailable: !!sharedSecretKeys[data.sender],
        ivLength: data.iv
          ? new Uint8Array(
              atob(data.iv)
                .split("")
                .map((char) => char.charCodeAt(0))
            ).length
          : "N/A",
        contentLength: data.content
          ? new Uint8Array(
              atob(data.content)
                .split("")
                .map((char) => char.charCodeAt(0))
            ).length
          : "N/A",
      });

      // Convert base64 back to ArrayBuffer
      const encryptedContent = new Uint8Array(
        atob(data.content)
          .split("")
          .map((char) => char.charCodeAt(0))
      );
      const iv = new Uint8Array(
        atob(data.iv)
          .split("")
          .map((char) => char.charCodeAt(0))
      );

      // Validate IV length (AES-GCM requires 12 bytes)
      if (iv.length !== 12) {
        throw new Error(
          `Invalid IV length. Expected 12 bytes, got ${iv.length}`
        );
      }

      // Decrypt the message
      const decryptedContent = await window.crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: iv,
        },
        sharedSecretKeys[data.sender],
        encryptedContent
      );

      // Convert decrypted content to string
      const decodedContent = new TextDecoder().decode(decryptedContent);

      // Append decrypted message
      appendMessage(
        data.sender,
        decodedContent,
        data.sender === "{{ username }}" ? "user" : "other"
      );
    } catch (error) {
      console.error("Comprehensive Decryption Failure:", {
        errorName: error.name,
        errorMessage: error.message,
        errorStack: error.stack,
        sender: data.sender,
        keyAvailable: !!sharedSecretKeys[data.sender],
        publicKeyAvailable: !!peerPublicKeys[data.sender],
      });
      appendMessage(
        "System",
        `Failed to decrypt message from ${data.sender}: ${error.message}`,
        "system"
      );
    }
  } else {
    // Fallback to regular message handling
    appendMessage(
      data.sender,
      data.content,
      data.sender === localStorage.getItem("username") ? "user" : "other"
    );
  }
});

socket.on("live_users", (data) => {
  const usersList = document.getElementById("usersList");
  usersList.innerHTML = "";
  data.users.forEach((user) => {
    if (user === "{{ username }}") {
      console.log("Current user:", user);
      return;
    }
    const userItem = document.createElement("li");
    userItem.textContent = user["name"];
    userItem.classList.add("list-group-item");
    userItem.id = `user-${user["name"]}`;
    usersList.appendChild(userItem);
    deriveSharedKey(window.privateKey, user["publicKey"]).then((sharedKey) => {
      if (sharedKey) {
        sharedSecretKeys[user["name"]] = sharedKey;
        appendMessage(
          "System",
          `Secure connection established with ${user["name"]}`,
          "system"
        );
        // console.log(JSON.stringify(sharedSecretKeys));

        // // save sharedSecretKeys to localStorage as base64
        // localStorage.setItem(
        //   "sharedSecretKeys",
        //   btoa(JSON.stringify(sharedSecretKeys))
        // );
      }
    });
  });
});

// Modify send button click to use secure messaging
sendBtn.addEventListener("click", () => {
  const content = messageInput.value.trim();
  if (content) {
    if (messageType.value === "private") {
      const recipientUser = recipient.value.trim();
      if (!recipientUser) {
        alert("Please specify a recipient");
        return;
      }

      // Use secure messaging for private messages
      sendSecureMessage(recipientUser, content);
    } else {
      // Regular group message
      socket.emit("message", {
        type: "group",
        content: content,
      });
    }

    appendMessage(localStorage.getItem("username"), content, true);

    messageInput.value = "";
  }
});

async function getPrivateKeyFromStorage() {
  const base64Key = localStorage.getItem("privateKey");

  if (!base64Key) {
    throw new Error("No private key found in localStorage.");
  }

  // Decode Base64 back to ArrayBuffer
  const binaryString = atob(base64Key);
  const keyBuffer = new Uint8Array(
    [...binaryString].map((char) => char.charCodeAt(0))
  ).buffer;

  // Import the private key
  return await window.crypto.subtle.importKey(
    "pkcs8", // Format used for private keys
    keyBuffer,
    {
      name: "ECDH",
      namedCurve: "P-256", // Curve name must match the key
    },
    true, // Make the key extractable if needed
    ["deriveKey", "deriveBits"]
  );
}

async function getPublicKeyFromStorage() {
  const base64Key = localStorage.getItem("publicKey");

  if (!base64Key) {
    throw new Error("No public key found in localStorage.");
  }

  // Decode Base64 back to ArrayBuffer
  const binaryString = atob(base64Key);
  const keyBuffer = new Uint8Array(
    [...binaryString].map((char) => char.charCodeAt(0))
  ).buffer;

  // Import the public key
  return await window.crypto.subtle.importKey(
    "raw", // Format used for public keys
    keyBuffer,
    {
      name: "ECDH",
      namedCurve: "P-256", // Curve name must match the key
    },
    true, // Make the key extractable if needed
    []
  );
}

async function generateKey() {
  if (window.privateKey) {
    return;
  }
  if (localStorage.getItem("privateKey")) {
    window.privateKey = await getPrivateKeyFromStorage();
    window.publicKey = await getPublicKeyFromStorage();
    window.publicKeyBase64 = localStorage.getItem("publicKey");
    return;
  }
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "ECDH",
      namedCurve: "P-256",
    },
    true,
    ["deriveKey", "deriveBits"]
  );
  window.privateKey = keyPair.privateKey;
  let privateKeyArray = await window.crypto.subtle.exportKey(
    "pkcs8",
    keyPair.privateKey
  );
  window.publicKey = await window.crypto.subtle.exportKey(
    "raw",
    keyPair.publicKey
  );
  //Save private and public keys to localStorage
  localStorage.setItem(
    "privateKey",
    btoa(String.fromCharCode.apply(null, new Uint8Array(privateKeyArray)))
  );
  localStorage.setItem(
    "publicKey",
    btoa(String.fromCharCode.apply(null, new Uint8Array(window.publicKey)))
  );
  window.publicKeyBase64 = btoa(
    String.fromCharCode.apply(null, new Uint8Array(window.publicKey))
  );
}

async function deriveSharedKey(privateKey, publicKeyBase64) {
  // Convert base64 public key back to ArrayBuffer
  const publicKeyBuffer = new Uint8Array(
    atob(publicKeyBase64)
      .split("")
      .map((char) => char.charCodeAt(0))
  );

  const importedPublicKey = await window.crypto.subtle.importKey(
    "raw",
    publicKeyBuffer,
    {
      name: "ECDH",
      namedCurve: "P-256",
    },
    true,
    []
  );

  // Derive the shared secret
  const sharedKey = await window.crypto.subtle.deriveKey(
    {
      name: "ECDH",
      public: importedPublicKey,
      private: privateKey,
    },
    privateKey,
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"]
  );

  // Export the shared key to base64 for logging and comparison
  const exportedSharedKey = await window.crypto.subtle.exportKey(
    "raw",
    sharedKey
  );
  const sharedKeyBase64 = btoa(
    String.fromCharCode.apply(null, new Uint8Array(exportedSharedKey))
  );

  console.log("Derived Shared Key (Base64):", sharedKeyBase64);

  return sharedKey;
}

async function sendSecureMessage(recipient, content) {
  if (!window.privateKey) {
    alert("Please generate a private key first");
  }

  if (!sharedSecretKeys[recipient]) {
    alert(
      `No secure connection established with ${recipient}. Please exchange keys first.`
    );
    return;
  }

  // Generate a random initialization vector (IV)
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  // Encrypt the message
  const encodedContent = new TextEncoder().encode(content);
  const encryptedContent = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    sharedSecretKeys[recipient],
    encodedContent
  );

  // Convert encrypted data to base64
  const encryptedBase64 = btoa(
    String.fromCharCode.apply(null, new Uint8Array(encryptedContent))
  );
  const ivBase64 = btoa(String.fromCharCode.apply(null, iv));

  // Send encrypted message
  socket.emit("message", {
    type: "private",
    recipient: recipient,
    content: encryptedBase64,
    iv: ivBase64,
    encrypted: true,
  });
}



logoutBtn.addEventListener("click", async () => {
  try {
    const response = await fetch("/logout");
    const data = await response.json();
    if (data.success) {
      window.location.href = "/";
    }
  } catch (error) {
    console.error("Error:", error);
  }
});

function appendMessage(sender, content, type) {
  const messageDiv = document.createElement("div");
  messageDiv.className = `message ${type}-message`;
  const timestamp = new Date().toLocaleTimeString();
  messageDiv.textContent = `[${timestamp}] ${sender}: ${content}`;
  messageContainer.appendChild(messageDiv);
  messageContainer.scrollTop = messageContainer.scrollHeight;
}

// Handle Enter key
messageInput.addEventListener("keypress", (e) => {
  if (e.key === "Enter") {
    sendBtn.click();
  }
});
