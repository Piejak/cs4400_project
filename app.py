from flask import Flask, render_template
import pymysql

app = Flask(__name__)

@app.route("/")
def hello():
    connection = pymysql.connect(host='academic-mysql.cc.gatech.edu',
                                 user='cs4400_Group_41',
                                 password='dfURMV5v',
                                 db='cs4400_Group_41',
    )
    try:
        with connection.cursor() as cursor:
            sql = 'SELECT * FROM User;'
            cursor.execute(sql)
            result = cursor.fetchall()
            print(result)
            return result[0]
    finally:
        connection.close()
    return "Hello World!"

@app.route("/welcome")
def welcome():
    return render_template('welcome.html')
