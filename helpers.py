import os
import requests
import urllib.parse

from flask import redirect, render_template, request, session
from functools import wraps
from time import gmtime, strftime
from cs50 import SQL

db = SQL("sqlite:///bali.db")

def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code

def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

def searchNymeria(urlLinkedin):
    api_key = os.environ.get("API_KEY")
    data = {
    'api_key': f'{api_key}',
    'linkedin_url': f'{urlLinkedin}'
    }
    
    response = requests.post('https://www.nymeria.io/api/v2/emails', data=data).json()
    print (response)
    if response["data"]["emails"] == []:
        insert(urlLinkedin, str(" "), str(" "), uid=session.get("user_id"))
        return None
    else:
        emails = {"professional" : [], "personal" : []}

        for x in response["data"]["emails"]:
            professional =  str("")
            personal = str("")

            if x["type"] == "professional":
                emails["professional"].append(x["email"])
                professional = x["email"]

            else:
                emails["personal"].append(x["email"])
                personal = x["email"]
        insert(urlLinkedin, str(emails["personal"]).replace("[","").replace("]", "").replace("'", ""), str(emails["professional"]).replace("[","").replace("]", "").replace("'", ""), session.get("user_id"))

    emails["source"] = "Nymeria"
    return emails

def check(x):
    try:
        str(x)
        print ("line 66")
        return x
        
    except None:
        print ("line 69")
        return " "

def insert(key, personal, professional, uid):
    print ("we,re here", "LINE 75", "____________________________________", key, personal, professional, uid )
    time = strftime("%Y-%m-%d %H:%M:%S", gmtime())
    db.execute(f"INSERT INTO leadsNymeria(userID, urlLinkedIn, personal_email, professional_email, date) VALUES({uid}, '{str(key)}', '{personal}', '{professional}', '{time}');")
    print ("succesfully inserted!")

def searchdb(key):
    d = db.execute(f"SELECT * FROM leadsNymeria WHERE urlLinkedin='{key}';")
    print ("FOUND!!!!!! ---", d)

    if not d:
        return None
    else:
        e = d[0]
        return e