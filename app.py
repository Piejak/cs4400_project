from flask import Flask, render_template, g, request, flash, session, redirect, url_for
import pymysql
import hashlib

SECRET_KEY = b'_5#y2L"F4Q8z\n\xec]/'
app = Flask(__name__)
app.config.from_object(__name__)

@app.route("/")
def hello():
    return "Hello World!"

@app.route("/welcome")
def welcome():
    return render_template('welcome.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Logs the user in."""
    # if g.user:
    #     return redirect(url_for('hello'))
    error = None
    if request.method == 'POST':
        user = query_db('''select * from User where
            username = %s''', [request.form['username']], one=True)
        if user is None:
            error = 'Invalid username'
        elif not check_password_hash(user[1],
                                     request.form['password']):
            error = 'Invalid password'
        else:
            flash('You were logged in')
            session['user_id'] = user[0]
            return redirect(url_for('hello'))
    return render_template('login.html', error=error)


def query_db(query, args=(), one=False):
    """Queries the database and returns a list of dictionaries."""
    connection = pymysql.connect(host='academic-mysql.cc.gatech.edu',
                                 user='cs4400_Group_41',
                                 password='dfURMV5v',
                                 db='cs4400_Group_41',
                                 )
    try:
        with connection.cursor() as cursor:
            cursor.execute(query, args)
            rv = cursor.fetchall()
            return (rv[0] if rv else None) if one else rv
    finally:
        connection.close()

def check_password_hash(real_hash, entered_password):
    m = hashlib.md5()
    m.update(entered_password.encode('utf-8'))
    return real_hash == m.hexdigest()
