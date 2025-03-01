console.log("Malware Scanner Extension Loaded");

const MALICIOUS_DOMAINS = [
  "emotet-malware.com",
  "socgholish.com",
  "icedid-banking-trojan.net",
];

// 기존 규칙 제거 후 새 규칙 추가
chrome.declarativeNetRequest.updateDynamicRules({
  removeRuleIds: [1, 2, 3],
  addRules: MALICIOUS_DOMAINS.map((domain, index) => ({
    id: index + 1,
    priority: 1,
    action: { type: "block" },
    condition: { urlFilter: domain, resourceTypes: ["main_frame"] },
  })),
});
