// background.js
// Chrome blocks content scripts from chrome.storage.session by default.
// This one line opens it up so the chat page can keep the label map there.

function allowSessionStorageInPages() {
  chrome.storage.session.setAccessLevel({ accessLevel: "TRUSTED_AND_UNTRUSTED_CONTEXTS" });
}

chrome.runtime.onInstalled.addListener(allowSessionStorageInPages); // first install / reload
chrome.runtime.onStartup.addListener(allowSessionStorageInPages);   // each browser start
