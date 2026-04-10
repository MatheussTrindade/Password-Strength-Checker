const input = document.getElementById("password");
const resultDiv = document.getElementById("result");
const bar = document.getElementById("strength-bar");

let timeout = null;

// 🔥 debounce (evita flood na API)
input.addEventListener("input", () => {
    clearTimeout(timeout);

    timeout = setTimeout(() => {
        checkPassword();
    }, 400);
});

async function checkPassword() {
    const password = input.value;

    // limpa UI se vazio
    if (!password) {
        bar.style.width = "0%";
        bar.className = "";
        resultDiv.innerHTML = "";
        return;
    }

    // 🔄 loading
    resultDiv.innerHTML = "<p>🔄 Analisando...</p>";

    try {
        const response = await fetch("/check", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ password })
        });

        const data = await response.json();

        // 🎯 BARRA DE FORÇA
        const percent = Math.min((data.score / 5) * 100, 100);
        bar.style.width = percent + "%";

        bar.classList.remove("weak", "medium", "strong");

        if (data.score <= 1) bar.classList.add("weak");
        else if (data.score <= 3) bar.classList.add("medium");
        else bar.classList.add("strong");

        // 🧠 AJUSTE DE SEGURANÇA (CRÍTICO)
        let strengthLabel = data.strength;

        if (data.pwned_count > 0) {
            strengthLabel = "Comprometida ⚠️";
        }

        let html = `<h2>${strengthLabel}</h2>`;

        // ⚠️ dica geral
        html += `<p style="color:#f59e0b;">
            ⚠️ Evite usar nomes ou palavras comuns com números (ex: "senha123")
        </p>`;

        // 🔐 vazamento
        if (data.pwned_count > 0) {
            html += `<p style="color:#ef4444;">
                ⚠️ Esta senha apareceu ${data.pwned_count} vezes em vazamentos
            </p>`;
        }

        // 📋 feedback técnico
        if (data.feedback.length > 0) {
            html += "<ul>";
            data.feedback.forEach(f => {
                html += `<li>${f}</li>`;
            });
            html += "</ul>";
        }

        resultDiv.innerHTML = html;

    } catch (error) {
        resultDiv.innerHTML = "<p style='color:red;'>Erro ao analisar senha</p>";
        console.error(error);
    }
}

// 👁️ toggle senha
function togglePassword() {
    input.type = input.type === "password" ? "text" : "password";
}