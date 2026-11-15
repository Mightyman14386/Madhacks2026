const entries = document.querySelector("#entries");
const fields = document.querySelector("#fields");
const status = document.querySelector("#status");

function row(entry = { text: "", type: "PERSON", caseSensitive: false }) {
  const wrapper = document.createElement("div");
  wrapper.className = "entry";
  const label = document.createElement("label");
  label.className = "term";
  label.textContent = "Term";
  const input = document.createElement("input");
  input.type = "text";
  input.maxLength = 200;
  input.required = true;
  input.value = entry.text;
  input.placeholder = "Alice Smith";
  label.append(input);
  const category = document.createElement("label");
  category.textContent = "Category";
  const select = document.createElement("select");
  for (const [value, title] of [["PERSON", "Person"], ["ORG", "Organization"], ["CONFIDENTIAL", "Confidential phrase"], ["WATCH", "Generic term"]]) {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = title;
    select.append(option);
  }
  select.value = entry.type;
  category.append(select);
  const caseLabel = document.createElement("label");
  caseLabel.className = "case";
  const checkbox = document.createElement("input");
  checkbox.type = "checkbox";
  checkbox.checked = entry.caseSensitive;
  caseLabel.append(checkbox, "Match case");
  const remove = document.createElement("button");
  remove.type = "button";
  remove.textContent = "Remove";
  remove.addEventListener("click", () => wrapper.remove());
  wrapper.append(label, category, caseLabel, remove);
  entries.append(wrapper);
}

function report(message, error = false) {
  status.textContent = message;
  status.dataset.error = String(error);
}

document.querySelector("#add").addEventListener("click", () => row());
document.querySelector("#settings").addEventListener("submit", async (event) => {
  event.preventDefault();
  const watchlist = [...entries.children].map((entry) => ({
    text: entry.querySelector("input[type=text]").value.trim(),
    type: entry.querySelector("select").value,
    caseSensitive: entry.querySelector("input[type=checkbox]").checked,
  }));
  fields.disabled = true;
  try {
    const result = await chrome.runtime.sendMessage({ type: "PG_SET_WATCHLIST", watchlist });
    if (!result?.ok) throw new Error(result?.error || "Could not save settings.");
    report("Saved on this device. New pastes will use this watchlist.");
  } catch (error) { report(error.message, true); }
  finally { fields.disabled = false; }
});

void (async () => {
  try {
    const result = await chrome.runtime.sendMessage({ type: "PG_GET_WATCHLIST" });
    if (!result?.ok) throw new Error(result?.error || "Could not load settings.");
    result.watchlist.forEach(row);
    fields.disabled = false;
    report("Ready. Add a term or edit your saved watchlist.");
  } catch (error) { report(`${error.message} Reload this settings page to retry.`, true); }
})();
