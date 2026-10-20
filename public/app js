const emailInput = document.querySelector("#email");
const checkForm = document.querySelector("#email-form");
const checkButton = document.querySelector("#check-button");
const sendButton = document.querySelector("#send-code");
const result = document.querySelector("#result");
const verifyForm = document.querySelector("#verify-form");
const verifyResult = document.querySelector("#verify-result");
let selectedEmail = "";

function showMessage(element, title, message, type = "") {
  element.className = `result ${type}`.trim();
  element.replaceChildren();
  const strong = document.createElement("strong");
  strong.textContent = title;
  const body = document.createElement("div");
  body.textContent = message;
  element.append(strong, body);
}

async function postJSON(url, payload) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || "Permintaan gagal.");
  return data;
}

checkForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const email = emailInput.value.trim().toLowerCase();
  selectedEmail = email;
  sendButton.disabled = true;
  verifyForm.classList.add("hidden");
  verifyResult.classList.add("hidden");
  checkButton.disabled = true;
  showMessage(result, "Sedang memeriksa…", "Memeriksa format dan konfigurasi domain.");
  try {
    const data = await postJSON("/api/check-domain", { email });
    showMessage(
      result,
      "Pemeriksaan dasar selesai",
      `Format: ${data.format}. DNS/MX: ${data.domainMx}. ${data.note}`,
      "success"
    );
    sendButton.disabled = false;
  } catch (error) {
    showMessage(result, "Pemeriksaan gagal", error.message, "error");
  } finally {
    checkButton.disabled = false;
  }
});

sendButton.addEventListener("click", async () => {
  if (!selectedEmail) return;
  sendButton.disabled = true;
  showMessage(verifyResult, "Memproses permintaan…", "Jika konfigurasi email tersedia, kode akan dikirim.");
  try {
    const data = await postJSON("/api/send-code", { email: selectedEmail });
    showMessage(verifyResult, "Permintaan diproses", data.message, "success");
    verifyForm.classList.remove("hidden");
  } catch (error) {
    showMessage(verifyResult, "Kode belum terkirim", error.message, "error");
    sendButton.disabled = false;
  }
});

verifyForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const code = document.querySelector("#code").value.trim();
  const submitButton = verifyForm.querySelector("button");
  submitButton.disabled = true;
  try {
    const data = await postJSON("/api/verify-code", { email: selectedEmail, code });
    showMessage(verifyResult, data.status, `${data.message} ${data.limitation}`, "success");
    verifyForm.classList.add("hidden");
  } catch (error) {
    showMessage(verifyResult, "Verifikasi belum berhasil", error.message, "error");
  } finally {
    submitButton.disabled = false;
  }
});

emailInput.addEventListener("input", () => {
  selectedEmail = "";
  sendButton.disabled = true;
  result.classList.add("hidden");
  verifyResult.classList.add("hidden");
  verifyForm.classList.add("hidden");
});
