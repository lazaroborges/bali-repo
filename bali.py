import os
import csv

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session, send_file, send_from_directory, safe_join, abort
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from helpers import apology, login_required, searchNymeria, check, insert, searchdb

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["CLIENT_CSVS"] = "output/"
Session(app)

if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///bali.db")

@app.route("/")
@login_required
def index():    
    return redirect ("/search")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    return apology("TODO")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
    return jsonify("TODO")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/search", methods=["GET", "POST"])
@login_required
def search():
    if request.method == "GET":
        return render_template("search.html")
    if request.method == "POST":
        data = searchdb(request.form.get("urlLinkedin"))
        print (data)
        if data is None: 
            data = searchNymeria(request.form.get("urlLinkedin"))           
        else:
            e = searchdb(request.form.get("urlLinkedin"))
            data = {"personal": e["personal_email"], "professional": e["professional_email"]}
            print ("line 186", data)

        if data is None:
            return apology("No info available!", 400)
        else:
            lpf = len(data["professional"])
            lps = len(data["personal"])
            return render_template ("searched.html", url= request.form.get("urlLinkedin"), data=data, lpf =lpf, lps = lps), 200
            
    return apology("TODO")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")
            email = request.form.get("email")
            confirmation = request.form.get("confirmation")

            ## Query DB for userlist name and append them to a list (because this library )
            usernameSquery = db.execute (f"SELECT username FROM users;")
            usernameslist = list()
            for x in usernameSquery:
                usernameslist.append(x["username"])

            if request.form.get("password") != request.form.get("confirmation"):
                return apology ("Type Same Password Humpty Dumpty!", 400)
            elif username == "":
                return apology ("Empty Username Humpty Dumpty!", 400)
            elif password == "" or confirmation == "":
                return apology ("Empty Password Humpty Dumpty!", 400)
            elif username in usernameslist:
                print ("line 224 - the line of truth of a poet once forgotten by his own people")
                return apology ("Username already in use", 400)
            else:
                hashed = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

                db.execute("INSERT INTO users(username, hash, email) VALUES (:user, :hashd, :email)", user=username, hashd=hashed, email=email)

                return redirect ("/login")
    else:
        return render_template("register.html"), 200


@app.route("/bulk", methods=["GET", "POST"])
@login_required
def bulk():
    if request.method == "GET":
        return render_template("bulk.html")
    if request.method == "POST":
        if not request.files["file1"]:
            return apology ("No file found!", 400)
        try:
            file1 = request.files["file1"].read().decode("utf-8")
            dictionary = {}          
            for x in file1.splitlines():
                dictionary[f"{x}"] = None

            for key, value in dictionary.items():                    
                    if searchdb(key) is None: 
                        dictionary[f"{key}"] = searchNymeria(key)                   
                    else:
                        e = searchdb(key)
                        dictionary[f"{key}"] = {"personal": e["personal_email"], "professional": e["professional_email"]}
                        print ("line 186", dictionary[f"{key}"])

            csvRow = ["urlLinkedIn", "personal_email", "professional_email"]
    
            with open('output/output.csv', 'w', newline='') as csvfile:
                spamwriter = csv.writer(csvfile)
                spamwriter.writerow(csvRow)
                uid = session.get("user_id")
                for key, value in dictionary.items():
                    if value is None:
                        spamwriter.writerow([key])                        
                    else:  
                        ps = str(value["personal"]).replace("[","").replace("]", "").replace("'", "")
                        pf = str(value["professional"]).replace("[","").replace("]", "").replace("'", "")
                        spamwriter.writerow([key, ps, pf]) 

        except Exception:
            return apology ("File error! 1", 400)

    print ("SUCCESS!!!!!!!!!!!!!!!!!!!!!!!")        
    flash("Successfully imported and researched file! - You will get the output.csv in seconds!")
    try:
        return send_from_directory (app.config["CLIENT_CSVS"], filename="output.csv", as_attachment=True)
    except FileNotFoundError:
        return apology ("No file found! 2", 400)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
