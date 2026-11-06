# Modelo técnico

Este documento descreve como o Password Strength Checker estima a força de uma senha. O objetivo é educacional: o modelo é simples o bastante para ser explicado em poucas linhas e realista o bastante para não classificar `Senha@2024` como segura.

## 1. Entropia de força bruta

Primeiro calculamos o tamanho do alfabeto a partir das classes de caractere presentes:

| Classe | Tamanho |
| --- | --- |
| Minúsculas ASCII | 26 |
| Maiúsculas ASCII | 26 |
| Dígitos | 10 |
| Símbolos ASCII | 33 |
| Qualquer caractere não ASCII | +100 |

```
entropia_bruta = comprimento × log2(alfabeto)
```

Esse é o teto: o custo de um ataque que testa todas as combinações. Atacantes reais não fazem isso. Eles começam pelo que é provável.

## 2. Detecção de padrões

Cada detector encontra trechos da senha e atribui a eles um **custo em bits**, o número aproximado de tentativas, em log2, que um atacante precisaria para chegar naquele trecho usando a estratégia certa.

| Padrão | Exemplo | Custo aproximado |
| --- | --- | --- |
| Palavra/senha comum | `senha`, `flamengo`, `123456` | `log2(tamanho da lista)` + bits de capitalização |
| Leet | `p@ssw0rd` | custo da palavra + 1 bit por substituição |
| Sequência | `abcd`, `4321` | `log2(26 ou 10)` + `log2(comprimento)` (+1 se decrescente) |
| Teclado | `qwerty`, `asdfgh` | `log2(47)` + `log2(comprimento)` |
| Repetição | `aaaa`, `abcabc` | custo do bloco base + `log2(repetições)` |
| Ano | `1990`, `2024` | `log2(150)` |
| Data | `15/03/1998`, `150398` | `log2(366 × 100)` |

**Capitalização:** só a primeira letra maiúscula, ou tudo maiúsculo, custa 1 bit. Maiúsculas espalhadas custam `log2(C(n, k))`, sendo `k` o número de maiúsculas no trecho.

**Leet:** a senha é normalizada com duas tabelas de substituição, porque `1` pode representar tanto `i` quanto `l`. As duas versões são comparadas com a lista.

## 3. Seleção dos padrões

Vários detectores podem disparar em trechos sobrepostos (`qwerty123` é ao mesmo tempo senha comum, padrão de teclado e sequência). Escolhemos os padrões de forma gulosa, priorizando o que gera maior **economia** para o atacante:

```
economia = (caracteres cobertos × log2(alfabeto)) − custo_do_padrão
```

Padrões que se sobrepõem a outros já escolhidos são descartados.

## 4. Entropia efetiva

```
entropia_efetiva = Σ caracteres não cobertos × log2(alfabeto)
                 + Σ custo dos padrões escolhidos
```

Exemplo, `Senha@2024`:

| Trecho | Tipo | Bits |
| --- | --- | --- |
| `Senha` | palavra comum + inicial maiúscula | ~8,6 |
| `@` | caractere livre (alfabeto 95) | ~6,6 |
| `2024` | ano | ~7,2 |
| **Total** | | **~22,4** (contra ~65,7 de força bruta) |

## 5. Score

| Score | Entropia efetiva | Classificação |
| --- | --- | --- |
| 0 | < 28 | Muito fraca |
| 1 | 28–35 | Fraca |
| 2 | 36–59 | Razoável |
| 3 | 60–79 | Forte |
| 4 | ≥ 80 | Muito forte |

Regras adicionais:

- Senhas com menos de 8 caracteres ficam limitadas ao score 1.
- Senhas encontradas no HIBP recebem score 0 e o rótulo "Comprometida". Senhas vazadas entram em listas de ataque, então a entropia teórica deixa de importar.

## 6. Tempo de quebra

Assumimos o **caso médio**: o atacante acerta depois de percorrer metade do espaço de busca.

```
tentativas = 2^(entropia_efetiva − 1)
tempo      = tentativas / taxa
```

| Cenário | Taxa | Representa |
| --- | --- | --- |
| Online, com limite | 10/s | Login com rate-limit ou bloqueio |
| Hash lento | 10⁴/s | Banco vazado com bcrypt, scrypt ou Argon2 |
| Hash rápido | 10¹⁰/s | Banco vazado com MD5 ou SHA-1, quebrado em GPU |

O expoente é limitado a 1000 para evitar overflow de ponto flutuante. Acima de 100 anos, o tempo aparece em faixas ("séculos", "milhares de anos", "milhões de anos", "mais que a idade do universo").

## 7. Verificação de vazamentos (k-anonymity)

Integração com a [Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords):

1. A senha é convertida em SHA-1 (`5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8`).
2. Só os primeiros 5 caracteres (`5BAA6`) são enviados para `/range/5BAA6`.
3. A API devolve centenas de sufixos com o mesmo prefixo, mais entradas falsas de preenchimento (header `Add-Padding: true`).
4. O sufixo é comparado localmente.

A API nunca recebe a senha nem o hash completo. As respostas são guardadas em cache por prefixo (LRU, 512 entradas), para não repetir requisições enquanto o usuário digita.

Se a consulta falha (rede, timeout, TLS), o resultado é `checked: false`. A interface informa que não conseguiu verificar, em vez de apresentar a senha como não vazada.

## 8. Limitações conhecidas

- **Wordlist pequena.** São cerca de 200 entradas, para manter o projeto leve e legível. Ferramentas de produção como o [zxcvbn](https://github.com/dropbox/zxcvbn) usam dezenas de milhares de entradas ranqueadas por frequência.
- **Sem contexto pessoal.** Nome, e-mail e datas do usuário não são considerados.
- **Padrões combinados.** Combinações como "palavra + palavra" são tratadas de forma independente. O modelo não soma o custo de escolher a estrutura.
- **Teclado.** Só detecta trechos contínuos de uma mesma linha do layout QWERTY. Diagonais como `1qaz2wsx` não são detectadas.
