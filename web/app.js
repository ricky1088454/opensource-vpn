const form = document.getElementById("proxy-form");
const urlInput = document.getElementById("url-input");
const statusNode = document.getElementById("status");
const frame = document.getElementById("page-frame");
const textOutput = document.getElementById("text-output");
const responsePre = document.getElementById("response-pre");

function setStatus(message, isError = false) {
  statusNode.textContent = message;
  statusNode.style.color = isError ? "#ff8a8a" : "#b9d3ff";
}

function renderHtml(url, html) {
  textOutput.hidden = true;
  const doc = `<base href="${url}">${html}`;
  frame.srcdoc = doc;
}

function renderText(content) {
  frame.srcdoc = "";
  textOutput.hidden = false;
  responsePre.textContent = content;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const target = urlInput.value.trim();
  if (!target) return;

  setStatus("Loading...");
  textOutput.hidden = true;

  try {
    const response = await fetch(`/api/fetch?url=${encodeURIComponent(target)}`);
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Request failed.");
    }

    if (data.contentType.toLowerCase().includes("text/html")) {
      renderHtml(data.url, data.content);
    } else {
      renderText(data.content);
    }
    setStatus(`Loaded: ${data.url}`);
  } catch (error) {
    frame.srcdoc = "";
    renderText("");
    setStatus(error.message, true);
  }
});
