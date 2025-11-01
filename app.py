from flask import Flask, render_template, jsonify, send_file
import json

app = Flask(__name__)

@app.route('/sitemap.xml', methods=['GET'])
def sitemap():
    return send_file('sitemap.xml', mimetype='application/xml')

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/dash")
def dasg():
    return render_template("dashboard.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
