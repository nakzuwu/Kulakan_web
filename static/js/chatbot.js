document.addEventListener("DOMContentLoaded", () => {
    const chatIcon = document.getElementById("chat-icon");
    const chatContainer = document.getElementById("chat-container");
    const chatMessages = document.getElementById("chat-messages");
    const chatForm = document.getElementById("chat-form");
    const chatInput = document.getElementById("chat-input");
  
    // Toggle chat visibility
    chatIcon.addEventListener("click", () => {
      chatContainer.classList.toggle("hidden");
    });
  
    // Handle form submission
    chatForm.addEventListener("submit", async (e) => {
      e.preventDefault();
  
      const userMessage = chatInput.value.trim();
      if (!userMessage) return;
  
      addMessageToChat("message", userMessage); // Add user message to chat
      chatInput.value = ""; // Clear input field
  
      try {
        const response = await fetch("/query", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message: userMessage }),
        });
  
        const data = await response.json();
        addMessageToChat(
          "AI",
          data.response || "Maaf, saya tidak dapat memahami permintaan Anda."
        );
      } catch (error) {
        addMessageToChat("AI", "Terjadi kesalahan. Silakan coba lagi nanti.");
      }
    });
  
    // Function to process and format AI messages
    const processMessage = (msg) => {
      const lines = msg.split("\n").filter((line) => line.trim() !== ""); // Split by lines
      let formattedMessage = "";
  
      lines.forEach((line) => {
        if (/^\d+\.\s/.test(line.trim())) {
          // If the line starts with "1." or "2." (numbered list)
          formattedMessage += <li>${line.replace(/^\d+\.\s/, "").trim()}</li>;
        } else {
          // If the line is a regular paragraph
          formattedMessage += <p>${line.trim()}</p>;
        }
      });
  
      // Wrap list items in <ol> if they exist
      if (formattedMessage.includes("<li>")) {
        formattedMessage = <ol style="margin-left: 20px;">${formattedMessage}</ol>;
      }
  
      return formattedMessage;
    };
  
    // Function to add messages to the chat
    const addMessageToChat = (sender, message) => {
      const messageDiv = document.createElement("div");
      messageDiv.className = "flex gap-3 my-4 text-gray-700";
  
      if (sender === "You") {
        messageDiv.className = "flex justify-end my-4 text-gray-700";
  
        const userMessageBubble = document.createElement("p");
        userMessageBubble.className =
          "bg-blue-100 p-4 border-4 border-black rounded-lg shadow-[2px_2px_0px_rgba(0,0,0,1)] text-right";
        userMessageBubble.style.wordWrap = "break-word"; // Bungkus kata panjang
        userMessageBubble.style.wordBreak = "break-word"; // Potong kata jika terlalu panjang
        userMessageBubble.style.whiteSpace = "pre-wrap"; // Pertahankan spasi dan baris baru
        userMessageBubble.textContent = message;
  
        messageDiv.appendChild(userMessageBubble);
        chatMessages.appendChild(messageDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight; // Auto-scroll ke bawah
      } else {
        // Format AI response
        const formattedMessage = processMessage(message);
  
        // Create typing effect for AI response
        const messageContent = document.createElement("div");
        messageContent.className =
          "bg-yellow-50 p-4 border-4 border-black rounded-lg shadow-[2px_2px_0px_rgba(0,0,0,1)]";
        messageContent.innerHTML = ""; // Start with empty content
  
        messageDiv.innerHTML = `
          <div class="rounded-full bg-[#006A67] w-10 h-10 flex items-center justify-center shadow-[2px_2px_0px_rgba(0,0,0,1)]">
            <svg
              stroke="none"
              fill="white"
              stroke-width="1.5"
              viewBox="0 0 24 24"
              aria-hidden="true"
              height="20"
              width="20"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09zM18.259 8.715L18 9.75l-.259-1.035a3.375 3.375 0 00-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 002.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 002.456 2.456L21.75 6l-1.035.259a3.375 3.375 0 00-2.456 2.456zM16.894 20.567L16.5 21.75l-.394-1.183a2.25 2.25 0 00-1.423-1.423L13.5 18.75l1.183-.394a2.25 2.25 0 001.423-1.423l.394-1.183.394 1.183a2.25 2.25 0 001.423 1.423l1.183.394-1.183.394a2.25 2.25 0 00-1.423 1.423z"
              ></path>
            </svg>
          </div>
        `;
  
        messageDiv.appendChild(messageContent);
        chatMessages.appendChild(messageDiv);
  
        let index = 0;
        const typingInterval = setInterval(() => {
          if (index < formattedMessage.length) {
            messageContent.innerHTML = formattedMessage.slice(0, index);
            index++;
            chatMessages.scrollTop = chatMessages.scrollHeight; // Auto-scroll to bottom
          } else {
            clearInterval(typingInterval); // Stop typing effect
          }
        }, 50); // Typing speed: 50ms per character
      }
    };
  });