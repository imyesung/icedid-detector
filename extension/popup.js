document.getElementById("scan").addEventListener("click", async function () {
  try {
    // Get current tab information
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = tab.url;

    // For demonstration, using a placeholder content string.
    const response = await fetch("http://127.0.0.1:5000/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: url,
        content: "Sample content from page" 
      }),
    });

    const result = await response.json();
    const statusElement = document.getElementById("status");

    if (result.detection_summary.static_analysis.malware_detected) {
      statusElement.textContent = `Warning: ${result.detection_summary.static_analysis.malware_type} detected!`;
      statusElement.style.color = "red";
      alert(`${result.detection_summary.static_analysis.malware_type} detected: ${result.detection_summary.static_analysis.description}`);
    } else {
      statusElement.textContent = "No malware detected";
      statusElement.style.color = "green";
    }
  } catch (error) {
    console.error("Error during scan:", error);
    document.getElementById("status").textContent = "Scan failed";
  }
});