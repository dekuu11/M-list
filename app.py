import os
from unittest import result

from dotenv import load_dotenv
load_dotenv()

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash
import requests
from flask import jsonify



from helper import login_required, lookup, look, rating

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Use signed cookies for session (works on Vercel's read-only filesystem).
# Set SECRET_KEY in Vercel env vars for production.
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")
app.config["SESSION_PERMANENT"] = False

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///database.db")

# API key for movie search (RapidAPI): set before running, e.g. in terminal:
#   export RAPIDAPI_KEY=your_rapidapi_key_here
# Or add to a .env file and load it (e.g. with python-dotenv).


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/logout")
@login_required
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/")
def main():
    # Check if user is logged in by presence of user_id (not session length;
    # Flask-Session can add extra keys, so len(session) != 1 when logged in)
    if session.get("user_id") is None:
        return render_template("main.html")
    return render_template("search-mobile.html")
    


@app.route("/signup", methods=["GET", "POST"])
def signup():
    """Register user"""

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        confirm = request.form.get("confirm")
        
        # Check that username isn't blank
        if not username  and not password and not confirm:
            return render_template("signup.html",a=0)

        if username:
            if not password:
                if not confirm:
                    return render_template("signup.html",d=0, username=username)
                return render_template("signup.html",d=1, username=username, confirm=confirm)
            
            if not confirm:
                return render_template("signup.html",d=2, username=username, password=password)

        if password:
            if not username:
                if not confirm:
                    return render_template("signup.html",d=3, password=password)
                return render_template("signup.html",d=4, password=password, confirm=confirm)

            if not confirm:
                return render_template("signup.html",d=2, username=username, password=password)
        
        if confirm:
            if not username:
                if not password:
                    return render_template("signup.html",d=5, confirm=confirm)
                return render_template("signup.html",d=4, password=password, confirm=confirm)

            if not password:
                return render_template("signup.html",d=1, username=username, confirm=confirm)
            
        # Check there is no same name in database
        names = db.execute("SELECT username FROM users WHERE username = ?", username)
        if len(names) == 1:
            return render_template("signup.html",i=0, password=password, confirm=confirm)

        # Check the two passwords are same
        if password != confirm:
            return render_template("signup.html",i=1, username=username, password=password)

        # generate the hash password to insert
        pwhash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

        # Inserting to the DataBase
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, pwhash)

        return redirect("/login")

    else:
        return render_template("signup.html")



@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        # Ensure username and password was submitted
        if not username and not password:
            return render_template("login.html",a=0)

        if not username:
            return render_template("login.html", d=0, password=password)

        if not password:
            return render_template("login.html", d=1, username=username)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            return render_template("login.html", i=0)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/search", methods=["GET"])
@login_required
def search():

    title = request.args.get("title")
    
    try:
        results = lookup(str(title))
        return render_template("result.html", results=results, title=title)
    except:
        return render_template("result.html", title=title)


@app.route("/add", methods=["POST"])
@login_required
def add():

    if request.method == "POST":

        title = request.form.get("title")
        # name = request.form.get("name")
        # date = request.form.get("date")
        # Type = request.form.get("type")
        # img = request.form.get("img")

        arr = ["/title/", "/"]

        for a in arr:
            title = title.replace(a, "")

        title = {"title": title}

        # try:
        #     rate = rating(title["name"])
        # except:
        #     rate = "N/A"

        own = db.execute("SELECT title FROM p_list WHERE user_id = ?", session["user_id"])

        if title in own:
            return jsonify({'error': 'Admin access is required'}), 401

        else:
            # db.execute("INSERT INTO p_list (user_id, name, title, date, type, rating, img) VALUES(?, ?, ?, ?, ?, ?, ?)", session["user_id"], name, title["name"], date, Type, rate, img)
            return jsonify({'success': 'good'}), 200
                   
    return redirect("/")

@app.route("/added", methods=["POST"])
@login_required
def added():

    if request.method == "POST":

        title = request.form.get("title")
        name = request.form.get("name")
        date = request.form.get("date")
        Type = request.form.get("type")
        img = request.form.get("img")

        arr = ["/title/", "/"]

        for a in arr:
            title = title.replace(a, "")

        title = {"name": title}

        try:
            rate = rating(title["name"])
        except:
            rate = "N/A"


        own = db.execute("SELECT name FROM p_list WHERE user_id = ?", session["user_id"])

        # if title in own:
        #     return jsonify({'error': 'Admin access is required'}), 401

        db.execute("INSERT INTO p_list (user_id, name, title, date, type, rating, img) VALUES(?, ?, ?, ?, ?, ?, ?)", session["user_id"], name, title["name"], date, Type, rate, img)
        return jsonify({'success': 'good'}), 200

    return redirect("/")


@app.route("/list")
@login_required
def plist():

    plist = db.execute("SELECT * FROM p_list WHERE user_id = ?", session["user_id"])
        # justwanttotakeappointment
    return render_template("list.html", lists=plist)

@app.route("/delete", methods=["GET", "POST"])
@login_required
def delete():

    if request.method == "POST":

        title = str(request.form.get("title"))
        db.execute("DELETE FROM p_list WHERE user_id = ? AND title = ?", session["user_id"], title)
        return redirect("/delete")

    else:
        plist = db.execute("SELECT * FROM p_list WHERE user_id = ?", session["user_id"])
        return render_template("delete.html", lists=plist)
        

@app.route("/account", methods=["GET"])
@login_required
def account():

    name = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])

    return render_template("account.html", name=name[0])


@app.route("/chgpass", methods=["POST"])
@login_required
def change_password():

    newpassword = request.form.get("newpass")
    confirmpassword = request.form.get("confirmpass")

    if not newpassword or not confirmpassword:
        return jsonify({'error': 'fill required field'}), 401

    if newpassword != confirmpassword:
        return  jsonify({'error': 'Add same pass'}), 402

    # generate the hash password to insert
    pwhash = generate_password_hash(confirmpassword, method='pbkdf2:sha256', salt_length=8)

    #change password)
    db.execute("UPDATE users SET hash = ? WHERE id = ?", pwhash, session["user_id"])

    return jsonify({'success': 'good'}), 200


@app.route("/about")
@login_required
def about():

    return render_template("aboutus.html")
