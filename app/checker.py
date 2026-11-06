"""Password analysis: entropy estimation, pattern detection and crack-time scenarios.

The model is intentionally simple and explainable:

1. Start from the brute-force entropy: ``length * log2(charset)``.
2. Detect patterns attackers try first (common words, leet, sequences,
   keyboard walks, repetitions, dates). Each pattern replaces the characters
   it covers with a much smaller "guess cost" in bits.
3. The resulting *effective entropy* drives the score and the crack-time
   estimates for three realistic attack scenarios.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from .services.pwned import check_password_pwned

WORDLIST_PATH = Path(__file__).parent / "data" / "common.txt"

MIN_TOKEN = 4  # shortest dictionary/keyboard token worth flagging

LEET_VARIANTS = (
    str.maketrans({"@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o",
                   "$": "s", "5": "s", "7": "t", "+": "t"}),
    str.maketrans({"@": "a", "4": "a", "3": "e", "1": "l", "|": "l", "0": "o",
                   "$": "s", "5": "s", "7": "t", "+": "t"}),
)

KEYBOARD_ROWS = ("1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm")

YEAR_RE = re.compile(r"(?<!\d)(?:19\d{2}|20[0-4]\d)(?!\d)")
DATE_RE = re.compile(
    r"(?<!\d)(?:0[1-9]|[12]\d|3[01])[-/.]?(?:0[1-9]|1[0-2])[-/.]?(?:19\d{2}|20\d{2}|\d{2})(?!\d)"
)
REPEAT_RE = re.compile(r"(.+?)\1+")

# (threshold in bits, label). Score is the index of the first threshold not reached.
LEVELS = (
    (28, "Muito fraca"),
    (36, "Fraca"),
    (60, "Razoável"),
    (80, "Forte"),
    (math.inf, "Muito forte"),
)

SCENARIOS = (
    ("online", 10),              # login with rate limiting
    ("offline_slow", 1e4),       # leaked bcrypt/scrypt/argon2 hashes
    ("offline_fast", 1e10),      # leaked MD5/SHA-1 hashes, GPU rig
)

PATTERN_LABELS = {
    "dictionary": "Palavra comum",
    "leet": "Palavra com substituições",
    "sequence": "Sequência",
    "keyboard": "Padrão de teclado",
    "repeat": "Repetição",
    "date": "Data ou ano",
}


@dataclass(frozen=True)
class Pattern:
    start: int
    end: int  # exclusive
    kind: str
    token: str
    bits: float

    def overlaps(self, other: "Pattern") -> bool:
        return self.start < other.end and other.start < self.end


@lru_cache(maxsize=1)
def _wordlist() -> frozenset[str]:
    lines = WORDLIST_PATH.read_text(encoding="utf-8").splitlines()
    return frozenset(
        line.strip().lower() for line in lines if line.strip() and not line.startswith("#")
    )


def _charset_size(password: str) -> int:
    size = 0
    if any(c.islower() and c.isascii() for c in password):
        size += 26
    if any(c.isupper() and c.isascii() for c in password):
        size += 26
    if any(c.isdigit() and c.isascii() for c in password):
        size += 10
    if any(c.isascii() and not c.isalnum() for c in password):
        size += 33
    if any(not c.isascii() for c in password):
        size += 100
    return max(size, 1)


def _case_bits(token: str) -> float:
    uppers = sum(c.isupper() for c in token)
    if uppers == 0:
        return 0.0
    if uppers == len(token) or (uppers == 1 and token[0].isupper()):
        return 1.0
    return math.log2(math.comb(len(token), uppers))


# --- detectors -------------------------------------------------------------

def _find_dictionary(password: str) -> list[Pattern]:
    words = _wordlist()
    base_bits = math.log2(len(words))
    lowered = password.lower()
    variants = {lowered: "dictionary"}
    for table in LEET_VARIANTS:
        variants.setdefault(lowered.translate(table), "leet")

    found: dict[tuple[int, int], Pattern] = {}
    n = len(password)
    for text, kind in variants.items():
        for i in range(n):
            for j in range(n, i + MIN_TOKEN - 1, -1):
                if (i, j) in found or text[i:j] not in words:
                    continue
                token = password[i:j]
                subs = sum(a != b for a, b in zip(lowered[i:j], text[i:j]))
                bits = base_bits + _case_bits(token) + subs
                found[(i, j)] = Pattern(i, j, "leet" if subs else "dictionary", token, bits)
    return list(found.values())


def _find_sequences(password: str) -> list[Pattern]:
    lowered = password.lower()
    patterns = []
    i, n = 0, len(lowered)
    while i < n - 2:
        a, b = lowered[i], lowered[i + 1]
        delta = ord(b) - ord(a)
        same_class = (a.isascii() and b.isascii()) and (
            (a.isdigit() and b.isdigit()) or (a.isalpha() and b.isalpha())
        )
        if delta not in (1, -1) or not same_class:
            i += 1
            continue
        j = i + 1
        while (
            j + 1 < n
            and ord(lowered[j + 1]) - ord(lowered[j]) == delta
            and lowered[j + 1].isdigit() == a.isdigit()
            and lowered[j + 1].isascii()
        ):
            j += 1
        length = j - i + 1
        if length >= 3:
            space = 10 if a.isdigit() else 26
            bits = math.log2(space) + math.log2(length) + (1 if delta < 0 else 0)
            patterns.append(Pattern(i, j + 1, "sequence", password[i : j + 1], bits))
        i = j
    return patterns


def _find_keyboard(password: str) -> list[Pattern]:
    lowered = password.lower()
    rows = KEYBOARD_ROWS + tuple(r[::-1] for r in KEYBOARD_ROWS)
    patterns = []
    n = len(lowered)
    for i in range(n):
        for j in range(n, i + MIN_TOKEN - 1, -1):
            chunk = lowered[i:j]
            if any(chunk in row for row in rows):
                bits = math.log2(47) + math.log2(len(chunk)) + _case_bits(password[i:j])
                patterns.append(Pattern(i, j, "keyboard", password[i:j], bits))
                break
    return patterns


def _find_repeats(password: str, charset: int) -> list[Pattern]:
    patterns = []
    for match in REPEAT_RE.finditer(password):
        if len(match.group(0)) < 3:
            continue
        base = match.group(1)
        repeats = len(match.group(0)) // len(base)
        bits = len(base) * math.log2(charset) + math.log2(repeats)
        patterns.append(Pattern(match.start(), match.end(), "repeat", match.group(0), bits))
    return patterns


def _find_dates(password: str) -> list[Pattern]:
    patterns = [
        Pattern(m.start(), m.end(), "date", m.group(0), math.log2(366 * 100))
        for m in DATE_RE.finditer(password)
    ]
    patterns += [
        Pattern(m.start(), m.end(), "date", m.group(0), math.log2(150))
        for m in YEAR_RE.finditer(password)
    ]
    return patterns


# --- scoring ---------------------------------------------------------------

def _select_patterns(candidates: list[Pattern], bits_per_char: float) -> list[Pattern]:
    """Greedy pick of non-overlapping patterns, biggest entropy reduction first."""

    def savings(p: Pattern) -> float:
        return (p.end - p.start) * bits_per_char - p.bits

    chosen: list[Pattern] = []
    for p in sorted(candidates, key=savings, reverse=True):
        if savings(p) > 0 and not any(p.overlaps(c) for c in chosen):
            chosen.append(p)
    return sorted(chosen, key=lambda p: p.start)


def estimate_entropy(password: str) -> tuple[float, list[Pattern]]:
    charset = _charset_size(password)
    bits_per_char = math.log2(charset)
    candidates = (
        _find_dictionary(password)
        + _find_sequences(password)
        + _find_keyboard(password)
        + _find_repeats(password, charset)
        + _find_dates(password)
    )
    patterns = _select_patterns(candidates, bits_per_char)
    covered = sum(p.end - p.start for p in patterns)
    entropy = (len(password) - covered) * bits_per_char + sum(p.bits for p in patterns)
    return entropy, patterns


def format_duration(seconds: float) -> str:
    if seconds < 1:
        return "menos de 1 segundo"
    units = (
        (60, "segundo", "segundos"),
        (60, "minuto", "minutos"),
        (24, "hora", "horas"),
        (365.25 / 12, "dia", "dias"),
        (12, "mês", "meses"),
        (100, "ano", "anos"),
    )
    value = seconds
    for size, singular, plural in units:
        if value < size:
            n = int(value)
            return f"{n} {singular if n == 1 else plural}"
        value /= size
    centuries = value  # value is now in centuries
    if centuries < 10:
        return "séculos"
    if centuries < 10_000:
        return "milhares de anos"
    if centuries < 1.38e8:
        return "milhões de anos"
    return "mais que a idade do universo"


def _crack_times(entropy: float) -> list[dict]:
    # Average case: an attacker finds it after searching half the space.
    guesses = 2 ** min(max(entropy - 1, 0), 1000)
    return [
        {"id": scenario, "seconds": guesses / rate, "display": format_duration(guesses / rate)}
        for scenario, rate in SCENARIOS
    ]


def _feedback(password: str, score: int, patterns: list[Pattern], pwned: int | None) -> list[str]:
    tips: list[str] = []
    kinds = {p.kind for p in patterns}

    if pwned:
        tips.append("Esta senha já apareceu em vazamentos. Não use em nenhuma conta.")
    if len(password) < 12:
        tips.append("Use pelo menos 12 caracteres. Comprimento pesa mais que complexidade.")
    if kinds & {"dictionary", "leet"}:
        tips.append("Evite palavras e senhas comuns, mesmo trocando letras por @, 0 ou 3.")
    if "sequence" in kinds:
        tips.append("Sequências como abc ou 123 são as primeiras combinações testadas.")
    if "keyboard" in kinds:
        tips.append("Padrões de teclado (qwerty, asdf) estão em toda lista de ataque.")
    if "date" in kinds:
        tips.append("Anos e datas são fáceis de adivinhar, principalmente se forem pessoais.")
    if "repeat" in kinds:
        tips.append("Repetir caracteres ou blocos quase não adiciona segurança.")
    if score < 3 and _charset_size(password) < 95:
        tips.append("Misture maiúsculas, números e símbolos para ampliar o espaço de busca.")
    if not tips:
        tips.append("Senha sólida. Guarde em um gerenciador e não reutilize em outros serviços.")
    return tips[:4]


def analyze_password(password: str) -> dict:
    entropy, patterns = estimate_entropy(password)

    score = next(i for i, (limit, _) in enumerate(LEVELS) if entropy < limit)
    if len(password) < 8:
        score = min(score, 1)
    label = LEVELS[score][1]

    pwned = check_password_pwned(password)
    if pwned:
        score, label = 0, "Comprometida"

    return {
        "score": score,
        "label": label,
        "entropy": round(entropy, 1),
        "length": len(password),
        "patterns": [
            {"type": p.kind, "label": PATTERN_LABELS[p.kind], "token": p.token}
            for p in patterns
        ],
        "crack_times": _crack_times(entropy),
        "pwned": {"checked": pwned is not None, "count": pwned or 0},
        "feedback": _feedback(password, score, patterns, pwned),
    }
