from flask import Flask, render_template, request, jsonify
from utils.analyzer import analyze_password, is_reused_password, estimate_crack_time

app = Flask(__name__)


@app.route("/")
def index():
    """Render main page"""
    return render_template("index.html")


@app.route("/check", methods=["POST"])
def check_password():
    """Handle password analysis"""

    data = request.get_json()
    password = data.get("password", "")

    # analyze password strength
    result = analyze_password(password)

    # check if reused
    reused = is_reused_password(password)

    # estimate crack time
    crack = estimate_crack_time(result["entropy"])

    response = {
        "strength": result["strength"],
        "entropy": result["entropy"],
        "reused": reused,
        "crack_time": crack
    }

    return jsonify(response)


if __name__ == "__main__":
    app.run(debug=True)