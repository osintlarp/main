from flask import Flask, render_template, jsonify
import json

app = Flask(__name__)

def load_endpoints():
    with open('endpoints.json', 'r') as f:
        return json.load(f)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/dash")
def dasg():
    return render_template("dashboard.html")

@app.route('/v1/api_endpoints', methods=['GET'])
def api_endpoints():
    endpoints = load_endpoints()
    return jsonify(endpoints)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
