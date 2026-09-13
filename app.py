import os

from dotenv import load_dotenv
from flask import Flask, redirect, render_template, request, session, url_for
from waitress import serve

load_dotenv()

from server.auth import authenticate_user, create_user, ensure_users_table

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret-key")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

if app.config["SECRET_KEY"] == "change-this-secret-key":
    raise RuntimeError("Set SECRET_KEY before starting the application.")

ensure_users_table()

@app.route('/')
def home():
    return render_template("auth.html", mode="login", error=None)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("auth.html", mode="register", error=None)

    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    if len(username) < 3 or len(username) > 40:
        return render_template("auth.html", mode="register", error="Username must be 3-40 characters.")
    if "@" not in email or len(email) > 254:
        return render_template("auth.html", mode="register", error="Enter a valid email address.")
    if len(password) < 8:
        return render_template("auth.html", mode="register", error="Password must be at least 8 characters.")
    if password != confirm_password:
        return render_template("auth.html", mode="register", error="Passwords do not match.")

    try:
        user = create_user(username, email, password)
    except ValueError as error:
        return render_template("auth.html", mode="register", error=str(error))

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    return redirect(url_for("dashboard"))

@app.route('/login', methods=['POST'])
def login():
    identifier = request.form.get("identifier", "").strip()
    password = request.form.get("password", "")
    user = authenticate_user(identifier, password)

    if user is None:
        return render_template("auth.html", mode="login", error="Invalid username/email or password.")

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("home"))
    return f"<h1>Welcome, {session['username']}!</h1><p><a href='/logout'>Log out</a></p>"


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

if __name__ == '__main__':
    serve(
        app,
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "8080")),
    )