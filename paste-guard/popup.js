// popup.js: the window that opens when you click the Paste Guard icon.
// It only shows settings and counts; it never sees any real pasted values.

const $ = (id) => document.getElementById(id);
let currentTab = null; // the tab the popup was opened from
let settings = null;   // last settings received from the background worker

// Friendly names for the counter chips: [one, many].
const TYPE_NAMES = {
  PERSON: ["name", "names"], ORG: ["org", "orgs"], CONFIDENTIAL: ["confidential", "confidential"],
  WATCH: ["watchlist", "watchlist"], EMAIL: ["email", "emails"], PHONE: ["phone", "phones"],
  CARD: ["card", "cards"], SSN: ["SSN", "SSNs"], IP: ["IP", "IPs"], KEY: ["key", "keys"], JWT: ["token", "tokens"],
};

// Send a message to the background worker and unwrap its answer.
async function send(message) {
  const result = await chrome.runtime.sendMessage(message);
  if (!result?.ok) throw new Error(result?.error || "Something went wrong. Try again.");
  return result;
}

function say(text, error = false) {
  $("message").textContent = text;
  $("message").dataset.error = String(error);
}

// The hostname of the current tab, if it's a normal https page.
function currentHost() {
  try {
    const url = new URL(currentTab?.url || "");
    return url.protocol === "https:" ? url.hostname : null;
  } catch { return null; }
}

// One row in the "Active sites" list.
function siteRow(host, builtIn) {
  const li = document.createElement("li");
  li.className = "site";
  const avatar = document.createElement("span");
  avatar.className = "avatar";
  avatar.textContent = host.replace(/^www\./, "")[0] || "?";
  const name = document.createElement("span");
  name.className = "host";
  name.textContent = host;
  name.title = host;
  li.append(avatar, name);

  if (builtIn) {
    const pill = document.createElement("span");
    pill.className = "pill";
    pill.textContent = "Built-in";
    li.append(pill);
  } else {
    const remove = document.createElement("button");
    remove.className = "remove";
    remove.type = "button";
    remove.textContent = "×";
    remove.title = `Stop protecting ${host}`;
    remove.setAttribute("aria-label", `Remove ${host}`);
    remove.addEventListener("click", async () => {
      try {
        render(await send({ type: "PG_REMOVE_SITE", site: host }));
        say(`Removed ${host}.`);
      } catch (error) { say(error.message, true); }
    });
    li.append(remove);
  }
  return li;
}

// Draw the whole popup from the latest settings.
function render(next) {
  settings = next;
  const allowed = [...new Set([...next.builtIn, ...next.sites])].filter(h => !(next.neverSites || []).includes(h));
  const total = allowed.length;

  $("enabled").disabled = false;
  $("enabled").checked = next.enabled;
  $("power").dataset.on = String(next.enabled);
  $("status-title").textContent = next.enabled ? "Protection on" : "Protection paused";
  $("status-sub").textContent = next.enabled
    ? `Guarding pastes on ${total} site${total === 1 ? "" : "s"}`
    : "Pastes pass through unchanged";

  $("count").textContent = next.protectedCount;
  $("types").replaceChildren(...Object.entries(next.byType).map(([type, n]) => {
    const chip = document.createElement("span");
    chip.className = "chip";
    const [one, many] = TYPE_NAMES[type] || [type, type];
    chip.textContent = `${n} ${n === 1 ? one : many}`;
    return chip;
  }));

  $("sites").replaceChildren(
    ...allowed.map((host) => siteRow(host, next.builtIn.includes(host))),
  );

  // Offer a one-click "add this site" when the current tab isn't covered yet.
  const host = currentHost();
  const covered = host && allowed.includes(host);
  $("add-current").hidden = !host || covered;
  if (host && !covered) $("add-current").textContent = `+ Protect ${host}`;
}

// Add a site. Chrome only shows its permission prompt if we ask right away
// inside the click, so there is no "await" before permissions.request.
function addSite(raw, isCurrentTab) {
  let host;
  try { host = pgNormalizeSite(raw); } catch (error) { say(error.message, true); return; }
  if (settings?.builtIn.includes(host) && !(settings.neverSites || []).includes(host)) { say(`${host} is already built in.`); return; }
  if (settings?.sites.includes(host)) { say(`${host} is already on the list.`); return; }

  chrome.permissions.request({ origins: [pgOriginFor(host)] })
    .then(async (granted) => {
      if (!granted) { say(`Permission declined, so ${host} wasn't added.`, true); return; }
      render(await send({ type: "PG_ADD_SITE", site: host }));
      $("site-input").value = "";
      if (isCurrentTab && currentTab) {
        chrome.tabs.reload(currentTab.id); // load Paste Guard into this tab now
        say(`Added ${host} and reloaded the tab.`);
      } else {
        say(`Added ${host}. Reload any open ${host} tabs to start.`);
      }
    })
    .catch((error) => say(error.message, true));
}

// ---------- Wire up the controls ----------
$("enabled").addEventListener("change", async (event) => {
  const wanted = event.target.checked;
  try {
    render(await send({ type: "PG_SET_ENABLED", enabled: wanted }));
    say("");
  } catch (error) {
    event.target.checked = !wanted; // put the switch back
    say(error.message, true);
  }
});

$("add-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const raw = $("site-input").value;
  addSite(raw, (() => { try { return pgNormalizeSite(raw) === currentHost(); } catch { return false; } })());
});
$("add-current").addEventListener("click", () => addSite(currentHost(), true));

const openSettings = () => chrome.runtime.openOptionsPage();
$("open-settings").addEventListener("click", openSettings);
$("open-settings-icon").addEventListener("click", openSettings);

// ---------- Load ----------
void (async () => {
  try {
    [currentTab] = await chrome.tabs.query({ active: true, currentWindow: true });
    render(await send({ type: "PG_GET_SETTINGS" }));
  } catch (error) {
    $("status-sub").textContent = "Could not load settings";
    say(`${error.message} Close and reopen this popup to retry.`, true);
  }
})();
