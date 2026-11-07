// Runs only on a finished page, only if "check login pages" was allowed. Returns nothing unless the page asks for a
// password / card / OTP. The page code is returned WITHOUT anything typed or pre-filled in its fields.
(() => {
  const secret = document.querySelector(
    'input[type="password"], input[autocomplete="cc-number"], input[autocomplete="one-time-code"], ' +
    'input[name*="card" i], input[name*="cvv" i], input[name*="otp" i], input[name*="pin" i]');
  if (!secret) return { hasSecretField: false };
  const clone = document.documentElement.cloneNode(true);
  clone.querySelectorAll("input, textarea, select").forEach((el) => {
    el.removeAttribute("value");
    if (el.tagName === "TEXTAREA") el.textContent = "";
  });
  let html = "<!doctype html>" + clone.outerHTML;
  if (html.length > 380000) html = html.slice(0, 380000);
  return { hasSecretField: true, html };
})();
