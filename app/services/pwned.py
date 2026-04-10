import hashlib
import requests
import urllib3

# ⚠️ desativa warning de SSL (só pra dev)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def check_password_pwned(password):
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

    prefix = sha1[:5]
    suffix = sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    headers = {
        "User-Agent": "CyberPasswordChecker"
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=5,
            verify=False  # Resolve problema de proxy corporativo, mas não recomendado para produção - Validar antes de usar em redes corporativas.
        )
        response.raise_for_status()
    except requests.RequestException as e:
        print("❌ ERRO NA REQUISIÇÃO:", e)
        return 0

    for line in response.text.splitlines():
        if ":" not in line:
            continue

        h, count = line.split(":")

        if h == suffix:
            return int(count)

    return 0