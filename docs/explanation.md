
---

# 🧠 explanation.md (NÍVEL ENGENHARIA / CYBER)

```markdown
# 🔍 Password Security Analyzer - Technical Explanation

## 🎯 Objetivo

Simular, de forma educacional, como sistemas reais avaliam a segurança de senhas considerando vetores comuns de ataque.

---

## 🧠 Estratégia de Avaliação

A análise combina três pilares principais:

### 1. Heurística de Complexidade

A senha é avaliada com base em:

- Comprimento
- Uso de:
  - Letras minúsculas
  - Letras maiúsculas
  - Números
  - Símbolos

Penalidades são aplicadas para padrões comuns:

- Senhas curtas (< 8 caracteres)
- Senhas compostas apenas por números
- Baixa diversidade de caracteres

---

### 2. Verificação contra Vazamentos

Integração com a API:

👉 https://haveibeenpwned.com/API/v3#PwnedPasswords

#### 🔐 Modelo utilizado: k-Anonymity

1. A senha é convertida em SHA-1
2. Apenas os primeiros 5 caracteres são enviados
3. A API retorna uma lista de possíveis matches
4. O restante do hash é comparado localmente

**Resultado:**
- A senha nunca é exposta completamente
- Privacidade preservada

--