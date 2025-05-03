chrome.runtime.onInstalled.addListener(() => {
    chrome.declarativeNetRequest.updateSessionRules({
      addRules: [
        {
          id: 1,
          priority: 1,
          action: {
            type: 'modifyHeaders',
            responseHeaders: [
              { header: 'content-security-policy', operation: 'remove' },
              { header: 'content-security-policy-report-only', operation: 'remove' }
            ]
          },
          condition: {
            urlFilter: "localhost:",
            resourceTypes: ["main_frame", "sub_frame"]
          }
        }
      ],
      removeRuleIds: [1]
    });
  });
  