from flask import Blueprint, jsonify, render_template, request

from .checker import analyze_password

MAX_PASSWORD_LENGTH = 256

main = Blueprint("main", __name__)


@main.get("/")
def index():
    return render_template("index.html")


@main.post("/check")
def check():
    payload = request.get_json(silent=True) or {}
    password = payload.get("password")

    if not isinstance(password, str) or not password:
        return jsonify(error="Envie o campo 'password' como texto não vazio."), 400
    if len(password) > MAX_PASSWORD_LENGTH:
        return jsonify(error=f"Limite de {MAX_PASSWORD_LENGTH} caracteres."), 400

    response = jsonify(analyze_password(password))
    response.headers["Cache-Control"] = "no-store"
    return response
