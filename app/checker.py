from .services.pwned import check_password_pwned


def check_password_strength(password):
    score = 0
    feedback = []

    # 🔻 Comprimento
    if len(password) < 8:
        score -= 2
        feedback.append("Senha muito curta (mínimo 8 caracteres)")
    else:
        score += 1

    # 🔢 Números
    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("Adicione números")

    # 🔠 Maiúsculas
    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("Adicione letras maiúsculas")

    # 🔣 Símbolos
    if any(not c.isalnum() for c in password):
        score += 1
    else:
        feedback.append("Adicione símbolos")

    # 🔁 Apenas números (fraca)
    if password.isdigit():
        score -= 2
        feedback.append("Senha composta apenas por números")

    # 🔒 Normalizar score antes da API
    score = max(score, 0)

    # 🔐 HIBP (chama UMA vez só)
    print("Chamando HIBP...")
    pwned_count = check_password_pwned(password)
    print("Resultado HIBP:", pwned_count)


    # 🎯 Classificação
    if score <= 1:
        strength = "Fraca ❌"
    elif score <= 3:
        strength = "Média ⚠️"
    else:
        strength = "Forte ✅"

    if pwned_count > 0:
        score = 0
    
    return {
        "score": score,
        "strength": strength,
        "feedback": feedback,
        #"crack_time": estimate_crack_time(password),
        "pwned_count": pwned_count
    }


# 🔥 Estimativa de tempo de quebra
#def estimate_crack_time(password):
##charset = 0

##if any(c.islower() for c in password): charset += 26
##if any(c.isupper() for c in password): charset += 26
##if any(c.isdigit() for c in password): charset += 10
##if any(not c.isalnum() for c in password): charset += 32

##if charset == 0:
###return "instantâneo ⚡"

##combinations = charset ** len(password)
##guesses_per_sec = 1_000_000_000

##seconds = combinations / guesses_per_sec

##return format_time(seconds)


#def format_time(seconds):
##if seconds < 1:
###return "instantâneo ⚡"
##elif seconds < 60:
###return f"{int(seconds)} segundos"
##elif seconds < 3600:
###return f"{int(seconds / 60)} minutos"
##elif seconds < 86400:
###return f"{int(seconds / 3600)} horas"
##elif seconds < 31536000:
###return f"{int(seconds / 86400)} dias"
##elif seconds < 31536000 * 100:
###return f"{int(seconds / 31536000)} anos"
##else:
##    return "milhares de anos 🔐"