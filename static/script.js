"use strict";

const $ = (id) => document.getElementById(id);

const input = $("password");
const toggleBtn = $("toggle");
const generateBtn = $("generate");
const copyBtn = $("copy");
const meter = $("meter");
const verdict = $("verdict");
const entropyEl = $("entropy");
const report = $("report");
const breachEl = $("breach");
const patternsEl = $("patterns");
const feedbackEl = $("feedback");

const DEBOUNCE_MS = 350;
const numberFormat = new Intl.NumberFormat("pt-BR");

const RULES = {
    length: (p) => [...p].length >= 12,
    lower: (p) => /[a-z]/.test(p),
    upper: (p) => /[A-Z]/.test(p),
    digit: (p) => /\d/.test(p),
    symbol: (p) => /[^A-Za-z0-9]/.test(p),
};

let debounceTimer = null;
let inflight = null;

/* ---------- analysis ---------- */

input.addEventListener("input", () => {
    const password = input.value;
    updateChecklist(password);
    copyBtn.hidden = !password;
    clearTimeout(debounceTimer);
    inflight?.abort(); // a stale response must never overwrite newer input

    if (!password) {
        resetReport();
        return;
    }

    meter.classList.add("is-loading");
    report.dataset.state = "loading";
    debounceTimer = setTimeout(() => analyze(password), DEBOUNCE_MS);
});

async function analyze(password) {
    const controller = new AbortController();
    inflight = controller;

    try {
        const response = await fetch("/check", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ password }),
            signal: controller.signal,
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || response.statusText);
        render(data);
    } catch (error) {
        if (error.name === "AbortError") return;
        renderError(error);
    } finally {
        if (!controller.signal.aborted) meter.classList.remove("is-loading");
    }
}

function render(data) {
    meter.dataset.score = String(data.score);
    verdict.textContent = data.label;
    entropyEl.textContent = `${Math.round(data.entropy)} bits de entropia`;

    for (const time of data.crack_times) {
        const cell = report.querySelector(`[data-scenario="${time.id}"] dd`);
        if (cell) cell.textContent = time.display;
    }

    if (!data.pwned.checked) {
        setBreach("unknown", "Não foi possível consultar a base de vazamentos agora.");
    } else if (data.pwned.count > 0) {
        const times = data.pwned.count === 1 ? "vez" : "vezes";
        setBreach("found", `Encontrada ${numberFormat.format(data.pwned.count)} ${times} em vazamentos públicos.`);
    } else {
        setBreach("clean", "Não aparece em vazamentos conhecidos.");
    }

    if (data.patterns.length) {
        fillList(patternsEl, data.patterns.map(patternItem));
    } else {
        fillList(patternsEl, [mutedItem("Nenhum padrão previsível encontrado.")]);
    }

    fillList(feedbackEl, data.feedback.map((tip) => textItem(tip)));
    report.dataset.state = "ready";
}

function renderError(error) {
    console.error(error);
    meter.dataset.score = "none";
    verdict.textContent = "Falha na análise";
    report.dataset.state = "ready";
    setBreach("unknown", "O servidor não respondeu. Tente novamente.");
}

function resetReport() {
    meter.classList.remove("is-loading");
    meter.dataset.score = "none";
    verdict.textContent = "Aguardando senha";
    entropyEl.textContent = "0 bits";
    report.dataset.state = "empty";
    report.querySelectorAll(".crack-row dd").forEach((cell) => (cell.textContent = "—"));
    setBreach("idle", "Nenhuma consulta feita ainda.");
    fillList(patternsEl, [mutedItem("—")]);
    fillList(feedbackEl, [mutedItem("—")]);
}

function updateChecklist(password) {
    document.querySelectorAll("#checklist [data-rule]").forEach((item) => {
        item.classList.toggle("ok", RULES[item.dataset.rule](password));
    });
}

/* ---------- DOM helpers (textContent only, never innerHTML) ---------- */

function setBreach(status, message) {
    breachEl.dataset.status = status;
    breachEl.textContent = message;
}

function fillList(list, items) {
    list.replaceChildren(...items);
}

function textItem(text) {
    const li = document.createElement("li");
    li.textContent = text;
    return li;
}

function mutedItem(text) {
    const li = textItem(text);
    li.className = "muted";
    return li;
}

function patternItem(pattern) {
    const li = document.createElement("li");
    const label = document.createElement("span");
    const token = document.createElement("code");
    label.textContent = pattern.label;
    token.textContent = pattern.token;
    li.append(label, token);
    return li;
}

/* ---------- visibility, generator, copy ---------- */

function setVisible(visible) {
    input.type = visible ? "text" : "password";
    toggleBtn.textContent = visible ? "Ocultar" : "Mostrar";
    toggleBtn.setAttribute("aria-pressed", String(visible));
}

toggleBtn.addEventListener("click", () => {
    setVisible(input.type === "password");
    input.focus();
});

const CHARSETS = [
    "abcdefghijkmnopqrstuvwxyz", // no "l"
    "ABCDEFGHJKLMNPQRSTUVWXYZ",  // no "I", "O"
    "23456789",                  // no "0", "1"
    "!#$%&*+-=?@^_",
];

// Uniform random integer in [0, max) without modulo bias.
function randomInt(max) {
    const limit = Math.floor(0x100000000 / max) * max;
    const buffer = new Uint32Array(1);
    do {
        crypto.getRandomValues(buffer);
    } while (buffer[0] >= limit);
    return buffer[0] % max;
}

function generatePassword(length = 20) {
    const all = CHARSETS.join("");
    const chars = CHARSETS.map((set) => set[randomInt(set.length)]);
    while (chars.length < length) chars.push(all[randomInt(all.length)]);

    for (let i = chars.length - 1; i > 0; i--) {
        const j = randomInt(i + 1);
        [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars.join("");
}

generateBtn.addEventListener("click", () => {
    input.value = generatePassword();
    setVisible(true);
    input.dispatchEvent(new Event("input"));
    input.focus();
});

copyBtn.addEventListener("click", async () => {
    try {
        await navigator.clipboard.writeText(input.value);
        copyBtn.textContent = "Copiado";
    } catch {
        copyBtn.textContent = "Não foi possível copiar";
    }
    setTimeout(() => (copyBtn.textContent = "Copiar"), 1600);
});
