# app.py
from flask import Flask, render_template, request, jsonify
from analyzer import analyze
from database import init_db, save_check, get_recent, get_stats
from awareness_data import SCAM_TYPES, EMERGENCY_STEPS

app = Flask(__name__)
init_db()                       # 🗄️ make sure the table exists on startup

MAX_LENGTH = 5000


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    text = ""
    if request.method == "POST":
        text = request.form.get("message", "").strip()[:MAX_LENGTH]
        if text:
            result = analyze(text)
            save_check(result)          # 💾 saves summary only, never the text
    return render_template("index.html", result=result, text=text)


@app.route("/history")
def history():
    return render_template("history.html", rows=get_recent(), stats=get_stats())


@app.route("/awareness")
def awareness():
    return render_template("awareness.html", scams=SCAM_TYPES, steps=EMERGENCY_STEPS)


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json(silent=True) or {}
    text = str(data.get("message", ""))[:MAX_LENGTH]
    return jsonify(analyze(text))


if __name__ == "__main__":
    app.run(debug=True)