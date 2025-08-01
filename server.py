from flask import Flask, request, jsonify

app = Flask(__name__)

# Dummy credential store
VALID_CREDENTIALS = {
    "foo": "MyC0mpl3xP@ss",
    "admin": "admin123"
}

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if VALID_CREDENTIALS.get(username) == password:
        return jsonify({"status": "success"}), 200
    else:
        return jsonify({"status": "fail"}), 401

if __name__ == "__main__":
    app.run(port=5000)
