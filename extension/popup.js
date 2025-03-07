document.getElementById("scan").addEventListener("click", async function () {
  try {
    // Get current tab information
    const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
    const url = tab.url;

    // Get content from the page
    const response = await fetch("http://127.0.0.1:5000/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        url: url,
        content: "Sample content from page" // In a real implementation, you'd get actual page content
      }),
    });

    const result = await response.json();

    const statusElement = document.getElementById("status");

    if (result.malware_detected) {
      statusElement.textContent = `Warning: ${result.malware_type} detected!`;
      statusElement.style.color = "red";
      alert(`${result.malware_type} detected: ${result.description}`);
    } else {
      statusElement.textContent = "No malware detected";
      statusElement.style.color = "green";
    }
  } catch (error) {
    console.error("Error during scan:", error);
    document.getElementById("status").textContent = "Scan failed";
  }
});