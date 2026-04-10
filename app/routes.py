from flask import Blueprint, render_template, request, jsonify
from .checker import check_password_strength

main = Blueprint('main', __name__)

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/check', methods=['POST'])
def check():
    data = request.get_json()
    password = data.get('password')

    result = check_password_strength(password)

    return jsonify(result)