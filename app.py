"""This program will open and navigate through browser pages"""

import webbrowser
import json
import logging
from datetime import datetime
from functools import wraps
from flask import Flask, request, render_template, redirect, flash, url_for, session
from passlib.hash import sha256_crypt

app = Flask(__name__)
app.secret_key = 'turtle'
USER_FILE = "users.json"

logging.basicConfig(
    filename = "failed_login_attempts.log",
    level = logging.INFO,
)

def login_required(f):
    """redirect user is not logged in"""
    @wraps(f)
    def login_required_wrap(*args, **kwargs):
        if "username" not in session:
            if request.endpoint != "login":
                flash("You must login first!", "error")
                return redirect(url_for('login'))
        return f(*args, **kwargs)
    return login_required_wrap

@app.route("/")
def home():
    """opens homepage"""
    date_time = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")

    #get username if logged in
    username = session.get('username')

    #display welcome message when logged in
    if username:
        welcome_message = f"Welcome, {username}!"
    else:
        welcome_message = "Welcome, please log in or register for free"

    return render_template("home.html", time = date_time,
                           welcome_message = welcome_message)

@app.route("/largest")
@login_required
def largest():
    """opens largest turtles page"""
    date_time = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
    return render_template("largest.html", time = date_time)

@app.route("/oldest")
@login_required
def oldest():
    """opens oldest turtles page"""
    date_time = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
    return render_template("oldest.html", time = date_time)

@app.route("/facts")
@login_required
def facts():
    """opens turtle facts page"""
    date_time = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
    return render_template("facts.html", time = date_time)

@app.route("/login", methods=["GET", "POST"])
@login_required
def login():
    """validates information and logs user in"""
    date_time = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")

    if request.method == "POST":
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()

        #load existing users
        users = load_users()
        #get ip address
        login_ip = request.remote_addr

        #check if credentials match
        if username in users:
            if sha256_crypt.verify(password, users[username]["password"]):
                session["username"] = username
                flash("Login successful!", "success")
                return redirect(url_for("home"))
            else:
                flash("Invalid username or password.", "error")
                logging.info(
                    "Failed login attempt - Date: %s, Time: %s, IP: %s",
                    datetime.now().strftime('%Y-%m-%d'),
                    datetime.now().strftime('%H:%M:%S'),
                    login_ip
                )
                return redirect(url_for("login"))
        else:
            flash("Invalid username or password.", "error")
            logging.info(
                "Failed login attempt - Date: %s, Time: %s, IP: %s",
                datetime.now().strftime('%Y-%m-%d'),
                datetime.now().strftime('%H:%M:%S'),
                login_ip
            )
            return redirect(url_for("login"))

    return render_template("login.html", time = date_time)

@app.route("/logout")
@login_required
def logout():
    """logs current user out if logged in"""
    session.clear()
    flash("You have successfully logged out!", "success")
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    """registers user if given email, username, and password"""
    date_time = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")

    if request.method == "POST":
        #pull data from forms
        email = request.form.get("email").strip()
        username = request.form.get("username").strip()
        password = request.form.get("password").strip()
        email_updates = "emailUpdates" in request.form

        #validates all required fields are met
        if not email or not username or not password:
            flash("All fields are required!", "error")
            return redirect(url_for("register"))

        #validate password
        password_errors = validate_password(password)
        if password_errors:
            for error in password_errors:
                flash(error, "error")
            return redirect(url_for("register"))

        #load existing users
        users = load_users()
        # load passwords
        common_passwords = load_common_passwords()

        #check for common password
        if password in common_passwords:
            flash("The chosen password is common. Please choose another password")
            return redirect(url_for("register"))

        #check for duplicate accounts
        if username in users or any(u["email"] == email for u in users.values()):
            flash("Username or email already exists!", "error")
            return redirect(url_for("register"))

        #hash the password
        hash_pass = sha256_crypt.hash(password)

        #add new user
        users[username] = {
            "email": email,
            "password": hash_pass,
            "email_updates": email_updates
        }

        print("Registration complete!")
        print(f"email: {email} \nusername: {username} \npassword: {password}")

        # save user
        save_users(users)
        flash("Registration successful!", "success")
        return redirect(url_for("home"))

    return render_template("register.html", time = date_time)

@app.route("/password_update", methods=["GET", "POST"])
@login_required
def password_update():
    """allows a user to update their password"""
    date_time = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")

    if request.method == "POST":
        current_password = request.form.get("current_password").strip()
        new_password = request.form.get("new_password").strip()
        confirm_password = request.form.get("confirm_password").strip()

        #load users
        users = load_users()
        #load passwords
        common_passwords = load_common_passwords()
        #get current user name
        username = session.get("username")

        #verify current password
        if not sha256_crypt.verify(current_password, users[username]["password"]):
            flash("Current password is incorrect.", "error")
            return redirect(url_for("password_update"))

        #check if password is a common password
        if new_password in common_passwords:
            flash("The chosen password is common. Please choose another password")
            return redirect(url_for("password_update"))

        #validate new password
        password_errors = validate_password(new_password)
        if password_errors:
            for error in password_errors:
                flash(error, "error")
            return redirect(url_for("password_update"))

        #confirm new pass and old pass are different
        if current_password == new_password:
            flash("New password must be different than old password")
            return redirect(url_for("password_update"))

        #confirm password
        if new_password != confirm_password:
            flash("New password and confirmation do not match", "error")
            return redirect(url_for("password_update"))

        #update password
        users[username]["password"] = sha256_crypt.hash(new_password)
        save_users(users)
        flash("Password updated successfully!", "success")
        return redirect(url_for("home"))

    return render_template("password_update.html", time=date_time)

def save_users(users):
    """saves user information"""
    with open(USER_FILE, "w", encoding="utf-8") as file:
        json.dump(users, file, indent=4)

def load_users():
    """load users from JSON file, create file if none exist."""
    try:
        with open(USER_FILE, "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        #if empty, create JSON object
        with open(USER_FILE, "w", encoding="utf-8") as file:
            file.write("{}")
        return {}
    except json.JSONDecodeError:
        #handle file corruption
        return {}

def load_common_passwords():
    """loads the common passwords from a txt file"""
    try:
        with open("CommonPassword.txt", "r", encoding="utf-8") as file:
            return set(line.strip() for line in file)
    except FileNotFoundError:
        return set()

def validate_password(password):
    """validates password is 12+ length, has digit, uppercase, lowercase
    digit, and special character"""
    errors = []
    if len(password) < 12:
        errors.append("Password must be at least 12 characters")
    if not any(char.isdigit() for char in password):
        errors.append("Password does not have any digits")
    if not any(char.isupper() for char in password):
        errors.append("Password does not have any uppercase")
    if not any(char.islower() for char in password):
        errors.append("Password does not have any lowercase")
    if all(char.isalnum() for char in password):
        errors.append("Password does not have any special characters")
    return errors

#automatically launch browser
if __name__ == "__main__":
    webbrowser.open("http://127.0.0.1:80/")
    app.run(port=80)
