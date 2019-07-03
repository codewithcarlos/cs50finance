import os
import datetime

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

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


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    stocks = db.execute("SELECT symbol, name, SUM(shares) as shares FROM purchased WHERE user_id=:user_id AND symbol != 'Cash Deposit' GROUP BY symbol, name",
                        user_id=session["user_id"])
    cash = db.execute("SELECT cash FROM users WHERE id = :user_id",
                      user_id=session["user_id"])
    # show general template if user hasn't made any transactions to date
    if not stocks:
        cash = db.execute("SELECT cash FROM users WHERE id = :user_id",
                          user_id=session["user_id"])

        return render_template("index.html", symbol='CASH', name='', shares='', price='', cash=usd(cash[0]['cash']),
                               grand_total=usd(cash[0]['cash']))

    # calculate total equity and render result to webpage
    equity = 0
    for stock in range(len(stocks)):
        symbol = stocks[stock]['symbol']
        price = round(float(lookup(symbol)['price']), 2)
        stocks[stock]['price'] = usd(price)
        total = price * stocks[stock]['shares']
        equity += total
        stocks[stock]['total'] = usd(total)

    return render_template("index.html", stocks=stocks, cash=usd(cash[0]['cash']), grand_total=usd(cash[0]['cash'] + equity))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Query for symbol
        q = lookup(request.form.get("symbol"))
        # check if symbol exists
        if (not q):
            return apology("INVALID SYMBOL", 400)
        # check if share value is valid
        shares = request.form.get("shares")
        if (not shares.isdigit()):
            return apology("Please enter a positive integer", 400)

        cash = db.execute("SELECT cash FROM users WHERE id = :user_id",
                          user_id=session["user_id"])
        # gather most recent stock prices
        symbol = q['symbol']
        name = q['name']
        price = round(float(q['price']), 2)
        transacted = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cost = price * int(shares)
        # check if user can afford purchase
        if (cost > cash[0]['cash']):
            return apology("CAN'T AFFORD", 400)

        # Store transaction to db
        result = db.execute("INSERT INTO purchased (user_id, symbol, name, shares, price, transacted) VALUES(:user_id, :symbol, :name, :shares, :price, :transacted)",
                            user_id=session["user_id"], symbol=symbol, name=name, shares=shares, price=price, transacted=transacted)

        db.execute("UPDATE users SET cash = cash - :cost WHERE id = :user_id",
                   user_id=session["user_id"], cost=cost)

        # Render output
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    stocks = db.execute("SELECT symbol, shares, price, transacted FROM purchased WHERE user_id = :user_id ORDER BY symbol",
                        user_id=session["user_id"])

    return render_template("history.html", stocks=stocks)


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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        if request.form.get("symbol") == '':
            return apology("MISSING SYMBOL", 400)
        # Query for symbol
        q = lookup(request.form.get("symbol"))
        # check if symbol exists
        if (not q):
            return apology("INVALID SYMBOL", 400)
        # Format information
        content = f"A share of {q['name']} ({q['symbol']}) costs {usd(q['price'])}."
        # Render output
        return render_template("quoted.html", output=content)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

         # Ensure password was submitted
        elif not request.form.get("confirmation"):
            return apology("must provide confirmation of password", 400)

        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if (password != confirmation):
            return apology("passwords don't match", 400)

        hashed = generate_password_hash(password)

        # Register user into db
        result = db.execute("INSERT INTO users (username, hash) VALUES(:username, :hashed)",
                            username=username, hashed=hashed)
        if not result:
            return apology("username already exists", 400)

        # Remember which user has logged in
        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Query for symbol
        if not request.form.get("symbol"):
            return apology("MISSING SYMBOL", 400)

        # get stock info
        q = lookup(request.form.get("symbol"))
        symbol = q['symbol']
        shares = request.form.get("shares")
        if (not shares.isdigit()):
            return apology("Please enter a positive integer", 400)

        shares_owned = db.execute("SELECT sum(shares) as shares FROM purchased WHERE user_id = :user_id AND symbol = :symbol",
                                  user_id=session["user_id"], symbol=symbol)

        if (int(shares) > shares_owned[0]['shares']):
            return apology("TOO MANY SHARES", 400)

        shares = int(shares) * -1
        name = q['name']
        price = round(float(q['price']), 2)
        transacted = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cost = price * shares
        cash = db.execute("SELECT cash FROM users WHERE id = :user_id",
                          user_id=session["user_id"])

        # Load sales transaction into db
        result = db.execute("INSERT INTO purchased (user_id, symbol, name, shares, price, transacted) VALUES(:user_id, :symbol, :name, :shares, :price, :transacted)",
                            user_id=session["user_id"], symbol=symbol, name=name, shares=shares, price=price, transacted=transacted)

        db.execute("UPDATE users SET cash = cash - :cost WHERE id = :user_id",
                   user_id=session["user_id"], cost=cost)

        # Render output
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        cash = db.execute("SELECT cash FROM users WHERE id = :user_id",
                          user_id=session["user_id"])
        symbols = db.execute("SELECT DISTINCT symbol FROM purchased WHERE user_id = :user_id ORDER BY symbol",
                             user_id=session["user_id"])

        return render_template("sell.html", stocks=symbols)


@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    """Change password"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure old password was submitted
        if not request.form.get("old_password"):
            return apology("must provide old password", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide new password", 400)

         # Ensure password was submitted
        elif not request.form.get("confirmation"):
            return apology("must provide confirmation of new password", 400)

        old_password = request.form.get("old_password")
        new_password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        check = db.execute("SELECT hash FROM users WHERE id = :user_id",
                           user_id=session["user_id"])[0]['hash']
        # confirm the user's old password first as a preventative security measure
        if not check_password_hash(check, old_password):
            return apology("wrong password", 400)

        if (new_password != confirmation):
            return apology("passwords don't match", 400)

        hashed = generate_password_hash(new_password)

        # update password
        result = db.execute("UPDATE users set hash = :hashed WHERE id = :user_id",
                            hashed=hashed, user_id=session["user_id"])

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("password.html")


@app.route("/cash", methods=["GET", "POST"])
@login_required
def cash():
    """Add cash"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        if not float(request.form.get("cash")):
            return apology("Please enter a positive number", 400)

        add_cash = round(float(request.form.get("cash")), 2)

        if (add_cash <= 0):
            return apology("Please enter a positive number", 400)

        current_cash = db.execute("SELECT cash FROM users WHERE id = :user_id",
                                  user_id=session["user_id"])
        # update the cash in the db
        db.execute("UPDATE users SET cash = cash + :add_cash WHERE id = :user_id",
                   user_id=session["user_id"], add_cash=add_cash)

        # Record cash transaction
        transacted = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        result = db.execute("INSERT INTO purchased (user_id, symbol, name, shares, price, transacted) VALUES(:user_id, :symbol, :name, :shares, :price, :transacted)",
                            user_id=session["user_id"], symbol='Cash Deposit', name='', shares=0, price=add_cash, transacted=transacted)
        # Render output
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("cash.html")


def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)


# listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
