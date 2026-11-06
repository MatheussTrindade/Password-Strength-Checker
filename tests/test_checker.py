import pytest

from app import checker
from app.checker import analyze_password, format_duration


def kinds(result):
    return {p["type"] for p in result["patterns"]}


@pytest.mark.parametrize(
    "password",
    ["Senha@2024", "123456789", "Flamengo10", "qwerty123", "P@ssw0rd!", "aaaaaaaaaaaa"],
)
def test_predictable_passwords_score_low(password):
    assert analyze_password(password)["score"] <= 1


def test_random_long_password_is_very_strong():
    result = analyze_password("q8$Lm#2vRt!9xKp@Wz4G")
    assert result["score"] == 4
    assert result["patterns"] == []


def test_detects_dictionary_and_year():
    assert {"dictionary", "date"} <= kinds(analyze_password("Senha@2024"))


def test_detects_leet_substitution():
    result = analyze_password("P@ssw0rd")
    assert "leet" in kinds(result)
    assert result["patterns"][0]["token"] == "P@ssw0rd"


def test_detects_sequence_keyboard_and_repeat():
    assert "sequence" in kinds(analyze_password("xyzk#abcdef"))
    assert "keyboard" in kinds(analyze_password("Asdfgh#9k"))
    assert "repeat" in kinds(analyze_password("Zk9#zzzzzz"))


def test_short_password_is_capped():
    assert analyze_password("Xq9#v!")["score"] <= 1


def test_patterns_reduce_entropy():
    weak, _ = checker.estimate_entropy("Senha@2024")
    random, _ = checker.estimate_entropy("Kx7@pQ2m!z")
    assert weak < random


def test_pwned_password_is_marked_compromised(monkeypatch):
    monkeypatch.setattr(checker, "check_password_pwned", lambda password: 42)
    result = analyze_password("q8$Lm#2vRt!9xKp@Wz4G")
    assert result["score"] == 0
    assert result["label"] == "Comprometida"
    assert result["pwned"] == {"checked": True, "count": 42}
    assert "vazamentos" in result["feedback"][0]


def test_unavailable_breach_lookup_is_not_reported_as_clean(monkeypatch):
    monkeypatch.setattr(checker, "check_password_pwned", lambda password: None)
    assert analyze_password("whatever")["pwned"] == {"checked": False, "count": 0}


def test_crack_times_are_ordered_by_attacker_speed():
    times = analyze_password("Correct-Horse-7")["crack_times"]
    assert [t["id"] for t in times] == ["online", "offline_slow", "offline_fast"]
    assert times[0]["seconds"] > times[1]["seconds"] > times[2]["seconds"]


def test_huge_entropy_does_not_overflow():
    result = analyze_password("x9$Q" * 64)
    assert result["crack_times"][2]["display"]


@pytest.mark.parametrize(
    "seconds, expected",
    [
        (0.2, "menos de 1 segundo"),
        (1, "1 segundo"),
        (90, "1 minuto"),
        (5 * 3600, "5 horas"),
        (3 * 86400, "3 dias"),
        (40 * 365.25 * 86400, "40 anos"),
        (500 * 365.25 * 86400, "séculos"),
        (1e30, "mais que a idade do universo"),
    ],
)
def test_format_duration(seconds, expected):
    assert format_duration(seconds) == expected
