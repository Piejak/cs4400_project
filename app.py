from flask import Flask, render_template, g, request, flash, session, redirect, url_for
import pymysql
import hashlib

SECRET_KEY = b'_5#y2L"F4Q8z\n\xec]/'
app = Flask(__name__)
app.config.from_object(__name__)


@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        g.user = query_db('select * from User where username = %s',
                          [session['user_id']], one=True)


def get_user_id(username):
    """Convenience method to look up the id for a username."""
    rv = query_db('select Username from User where Username = %s',
                  username, one=True)
    return rv[0] if rv else None

@app.route("/")
def hello():
    return render_template('home.html')

@app.route("/welcome")
def welcome():
    return render_template('welcome.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registers the user."""
    if g.user:
        return redirect(url_for('hello'))
    error = None
    if request.method == 'POST':
        if not request.form['username']:
            error = 'You have to enter a username'
        elif not request.form['email'] or \
                '@' not in request.form['email']:
            error = 'You have to enter a valid email address'
        elif not request.form['password']:
            error = 'You have to enter a password'
        elif request.form['password'] != request.form['password2']:
            error = 'The two passwords do not match'
        elif get_user_id(request.form['username']) is not None:
            error = 'The username is already taken'
        else:
            
            post_db('''insert into User (
              Username, Password) values (%s, %s, FALSE);''',
                       [request.form['username'], generate_password_hash(request.form['password'])])
            flash('You were successfully registered and can login now')
            return redirect(url_for('login'))
    return render_template('register.html', error=error)

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


@app.route('/logout')
def logout():
    """Logs the user out."""
    flash('You were logged out')
    session.pop('user_id', None)
    return redirect(url_for('hello'))


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

def post_db(query, args=()):
    connection = pymysql.connect(host='academic-mysql.cc.gatech.edu',
                                 user='cs4400_Group_41',
                                 password='dfURMV5v',
                                 db='cs4400_Group_41',
                                 )
    try:
        with connection.cursor() as cursor:
            cursor.execute(query, args)
            cursor.commit()
    finally:
        connection.close()


def check_password_hash(real_hash, entered_password):
    m = hashlib.md5()
    m.update(entered_password.encode('utf-8'))
    return real_hash == m.hexdigest()

def generate_password_hash(entered_password):
    m = hashlib.md5()
    m.update(entered_password.encode('utf-8'))
    return m.hexdigest()
