# 🔐 Password Security Analyzer

Uma ferramenta web para análise de segurança de senhas baseada em heurísticas reais utilizadas em ataques modernos.

---

## 🚀 Features

- 🔍 Análise de força da senha (heurística realista)
- 📊 Barra visual estilo SaaS
- ⚠️ Detecção de senhas vazadas (API Have I Been Pwned)
- 🧠 Feedback inteligente (boas práticas de segurança)
- 👁️ Toggle de visualização da senha
- ⚡ Debounce para evitar flood na API

---

## 🧠 Como funciona

A ferramenta combina múltiplos fatores:

- Comprimento da senha
- Complexidade de caracteres
- Padrões fracos (ex: apenas números)
- Presença em vazamentos públicos
- Estimativa matemática de entropia

---

## 🛠️ Stack

- Python (Flask)
- JavaScript (Vanilla)
- HTML + CSS (UI estilo SaaS)
- API: Have I Been Pwned (Pwned Passwords)

---

## ⚙️ Como rodar localmente

```bash
git clone https://github.com/seu-usuario/password-security-analyzer.git
cd password-security-analyzer

pip install -r requirements.txt

python run.py

#http://127.0.0.1:5000