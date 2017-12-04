import pymysql
import hashlib
import random
import re
from datetime import datetime
from flask import Flask, render_template, g, request, flash, session, redirect, url_for, abort

SECRET_KEY = b'_5#y2L"F4Q8z\n\xec]/'
app = Flask(__name__)
app.config.from_object(__name__)


@app.before_request
def before_request():
    g.user = None
    g.admin = False
    if 'user_id' in session:
        g.user = query_db('select * from User where username = %s',
                          [session['user_id']], one=True)
        admin_lookup = query_db('''select IsAdmin from User where username = %s''', [session['user_id']], one=True)
        if admin_lookup[0] == 1:
            g.admin = True


def get_user_id(username):
    """Convenience method to look up the id for a username."""
    rv = query_db('select Username from User where Username = %s',
                  username, one=True)
    return rv[0] if rv else None

@app.route("/")
def home():
    if g.admin:
        return redirect(url_for('station_management'))
    elif g.user:
        return redirect(url_for('user_home'))
    else:
        return redirect(url_for('login'))

@app.route("/userHome")
def user_home():
    if g.admin or not g.user:
        return redirect(url_for('home'))
    start_stations = query_db('''select Name, EnterFare from Station;''')
    onTrip = '''select StartsAt from Trip where BreezecardNum in (select BreezecardNum from Breezecard where BelongsTo="{}") and EndsAt is NULL'''.format(session['user_id'])
    start_station = query_db(onTrip, one=True)
    start_station_name = None
    end_stations = None
    if start_station:
        start_station = start_station[0]
        end_stations = query_db('''select Name from Station where IsTrain=(select IsTrain from Station where StopID="{}")'''.format(start_station))
        start_station_name = query_db('''select Name from Station where StopID="{}"'''.format(start_station), one=True)[0]
    return render_template('userHome.html', breezeCards=query_db('''select BreezecardNum, Value from Breezecard where BelongsTo = %s and BreezecardNum not in (select BreezecardNum from Conflict);''', session['user_id']), startStations=start_stations, startStation=start_station_name, endStations=end_stations)

@app.route('/manageCards', methods=['GET', 'POST'])
def user_manage_cards():
    if g.admin or not g.user:
        return redirect(url_for('home'))

    if request.method == 'POST':
        if request.form['cardNum']:
            current_holder = query_db('''select BelongsTo from Breezecard where BreezecardNum={}'''.format(request.form['cardNum']), one=True)
            if current_holder:
                current_holder = current_holder[0]
                post_db('''insert into Conflict values ("{}", {}, "{}")'''.format(session['user_id'], request.form['cardNum'], str(datetime.now())))
            else:
                in_db = query_db('''select BreezecardNum from Breezecard where BreezecardNum={}'''.format(request.form['cardNum']), one=True)
                if in_db:
                    post_db('''update Breezecard set BelongsTo="{}" where BreezecardNum={}'''.format(session['user_id'], request.form['cardNum']))
                else:
                    post_db('''insert into Breezecard values ({}, 0.00, "{}")'''.format(request.form['cardNum'], session['user_id']))
    return render_template('userManageCards.html', breezeCards=query_db('''select BreezeCardNum, Value from Breezecard where BelongsTo = %s and BreezecardNum not in (select BreezecardNum from Conflict);''', session['user_id']))


@app.route('/usercards/<breezecard>', methods=['GET', 'POST'])
def add_funds(breezecard):
    if not g.user or g.admin:
        return redirect(url_for('home'))
    if query_db('''select BelongsTo from Breezecard where BreezecardNum = %s''', breezecard, one=True)[0] != session['user_id']:
        #if the breezecard doesnt belong to the logged in user
        return redirect(url_for('home'))
    card_info = query_db('''select BreezecardNum, Value from Breezecard where BreezecardNum = %s''', breezecard, one=True)
    if request.method == 'POST':
        #TODO: validate input
        post_db('''update Breezecard set Value= Value + {} where BreezecardNum={} limit 1'''.format(float(request.form['value']), breezecard))
        return redirect(url_for('user_manage_cards'))
    return render_template('addFunds.html', cardInfo=card_info)

@app.route('/cardDelete/<breezecard>')
def delete_card(breezecard):
    if not g.user or g.admin:
        return redirect(url_for('home'))
    if query_db('''select BelongsTo from Breezecard where BreezecardNum = %s''', breezecard, one=True)[0] != session['user_id']:
        #if the breezecard doesnt belong to the logged in user
        return redirect(url_for('home'))
    number_cards = query_db('''select count(BreezecardNum) from Breezecard where BelongsTo=%s group by BelongsTo''', session['user_id'], one=True)[0]
    if number_cards == 1:
        return redirect(url_for('user_manage_cards'))
    post_db('''update Breezecard set BelongsTo=NULL where BreezecardNum=%s limit 1''', breezecard)
    return redirect(url_for('user_manage_cards'))

@app.route('/tripHistory', methods=['GET', 'POST'])
def trip_history():
    if g.admin or not g.user:
        return redirect(url_for(home))
    if request.method == 'POST':
        if request.form['startTime'] and request.form['endTime']:
            #we have both start and end time
            return render_template('tripHistory.html', trips=query_db('''select * from Trip where (BreezecardNum in (select BreezecardNum from Breezecard where BelongsTo = %s)) AND (StartTime < %s) AND (StartTime > %s);''', [session['user_id'], request.form['endTime'], request.form['startTime']]))
        elif request.form['startTime']:
            #we just have start time
            return render_template('tripHistory.html', trips=query_db('''select * from Trip where (BreezecardNum in (select BreezecardNum from Breezecard where BelongsTo = %s)) AND (StartTime > %s);''', [session['user_id'], request.form['startTime']]))
        elif request.form['endTime']:
            #we just have end time
            return render_template('tripHistory.html', trips=query_db('''select * from Trip where (BreezecardNum in (select BreezecardNum from Breezecard where BelongsTo = %s)) AND (StartTime < %s);''', [session['user_id'], request.form['endTime']]))
    return render_template('tripHistory.html', trips=query_db('''select * from Trip where BreezecardNum in (select BreezecardNum from Breezecard where BelongsTo = %s)''', session['user_id']))

@app.route("/suspendedCards")
def suspended_cards():
    if not g.admin:
        return redirect(url_for('home'))
    suspended = query_db('''select Username, Conflict.BreezecardNum, DateTime, BelongsTo from Conflict, Breezecard where Breezecard.BreezecardNum=Conflict.BreezecardNum;;''')
    return render_template('suspendedCards.html', cards=suspended)

@app.route('/assignCard')
def assign_card():
    if not g.admin:
        return redirect(url_for('home'))
    username = request.args.get('username')
    breezecard = request.args.get('breezecard')
    post_db('''update Breezecard set BelongsTo="{}" where BreezecardNum={} limit 1'''.format(username, breezecard))
    post_db('''delete from Conflict where BreezecardNum={}'''.format(breezecard))
    return redirect(url_for('suspended_cards'))


@app.route('/cardManagement', methods=['GET', 'POST'])
def card_management():
    if not g.admin:
        return redirect(url_for('home'))

    cards = query_db(
        '''select * from Breezecard where BreezecardNum not in (select BreezecardNum from Conflict);''')
    if request.method == 'POST':
        print(request.form.get('suspendedCards'))
        if not request.form.get('suspendedCards'):
            query_string = '''select * from Breezecard where BreezecardNum not in (select BreezecardNum from Conflict);'''
            if request.form['cardNum']:
                query_string = '''select * from Breezecard where BreezecardNum not in (select BreezecardNum from Conflict) and BreezecardNum={};'''.format(
                    request.form['cardNum'])
            elif request.form['owner'] and request.form['startVal'] and request.form['endVal']:
                query_string = '''select * from Breezecard where BelongsTo="{}" and Value >= {} and Value <= {} and BreezecardNum not in (select BreezecardNum from Conflict);'''.format(
                    request.form['owner'], request.form['startVal'], request.form['endVal'])
            elif request.form['owner'] and request.form['endVal']:
                query_string = '''select * from Breezecard where BelongsTo="{}" and Value <= {} and BreezecardNum not in (select BreezecardNum from Conflict);'''.format(
                    request.form['owner'], request.form['endVal'])
            elif request.form['owner'] and request.form['startVal']:
                query_string = '''select * from Breezecard where BelongsTo="{}" and Value >= {} and BreezecardNum not in (select BreezecardNum from Conflict);'''.format(
                    request.form['owner'], request.form['startVal'])
            elif request.form['endVal'] and request.form['startVal']:
                query_string = '''select * from Breezecard where Value <= {} and Value >= {} and BreezecardNum not in (select BreezecardNum from Conflict);'''.format(
                    request.form['endVal'], request.form['startVal'])
            elif request.form['startVal']:
                query_string = '''select * from Breezecard where Value >= {} and BreezecardNum not in (select BreezecardNum from Conflict);'''.format(
                    request.form['startVal'])
            elif request.form['endVal']:
                query_string = '''select * from Breezecard where Value <= {} and BreezecardNum not in (select BreezecardNum from Conflict);'''.format(
                    request.form['endVal'])
            elif request.form['owner']:
                query_string = '''select * from Breezecard where BelongsTo="{}" and BreezecardNum not in (select BreezecardNum from Conflict);'''.format(
                    request.form['owner'])
        else:
            query_string = '''select * from Breezecard;'''
            if request.form['cardNum']:
                query_string = '''select * from Breezecard where BreezecardNum={};'''.format(
                    request.form['cardNum'])
            elif request.form['owner'] and request.form['startVal'] and request.form['endVal']:
                query_string = '''select * from Breezecard where BelongsTo="{}" and Value >= {} and Value <= {};'''.format(
                    request.form['owner'], request.form['startVal'], request.form['endVal'])
            elif request.form['owner'] and request.form['endVal']:
                query_string = '''select * from Breezecard where BelongsTo="{}" and Value <= {};'''.format(
                    request.form['owner'], request.form['endVal'])
            elif request.form['owner'] and request.form['startVal']:
                query_string = '''select * from Breezecard where BelongsTo="{}" and Value >= {};'''.format(
                    request.form['owner'], request.form['startVal'])
            elif request.form['endVal'] and request.form['startVal']:
                query_string = '''select * from Breezecard where Value <= {} and Value >= {};'''.format(
                    request.form['endVal'], request.form['startVal'])
            elif request.form['startVal']:
                query_string = '''select * from Breezecard where Value >= {};'''.format(
                    request.form['startVal'])
            elif request.form['endVal']:
                query_string = '''select * from Breezecard where Value <= {};'''.format(
                    request.form['endVal'])
            elif request.form['owner']:
                query_string = '''select * from Breezecard where BelongsTo="{}";'''.format(
                    request.form['owner'])
        if request.form['cardNum']:
            query_string = '''select * from Breezecard where BreezecardNum={};'''.format(request.form['cardNum'])
        elif request.form['owner'] and request.form['startVal'] and request.form['endVal']:
            query_string = '''select * from Breezecard where BelongsTo="{}" and Value >= {} and Value <= {};'''.format(request.form['owner'], request.form['startVal'], request.form['endVal'])
        elif request.form['owner'] and request.form['endVal']:
            query_string ='''select * from Breezecard where BelongsTo="{}" and Value <= {};'''.format(request.form['owner'], request.form['endVal'])
        elif request.form['owner'] and request.form['startVal']:
            query_string = '''select * from Breezecard where BelongsTo="{}" and Value >= {};'''.format(request.form['owner'], request.form['startVal'])
        elif request.form['endVal'] and request.form['startVal']:
            query_string = '''select * from Breezecard where Value <= {} and Value >= {};'''.format(request.form['endVal'], request.form['startVal'])
        elif request.form['startVal']:
            query_string = '''select * from Breezecard where Value >= {};'''.format(request.form['startVal'])
        elif request.form['endVal']:
            query_string = '''select * from Breezecard where Value <= {};'''.format(request.form['endVal'])
        elif request.form['owner']:
            query_string = '''select * from Breezecard where BelongsTo="{}";'''.format(request.form['owner']) 
        cards = query_db(query_string)
    return render_template('cardManagement.html', cards=cards)

@app.route('/admincards/<breezecard>', methods=['GET', 'POST'])
def admin_card_view(breezecard):
    if not g.admin:
        return redirect(url_for('home'))
    card_info = query_db(
        '''select * from Breezecard where BreezecardNum = %s''', breezecard, one=True)
    if request.method == 'POST':
        #TODO: validate input
        post_db('''update Breezecard set Value=%s, BelongsTo=%s where BreezecardNum=%s limit 1''', [(request.form['value'] if request.form['value'] else card_info[1]), (request.form['username'] if request.form['username'] else card_info[2]), breezecard])
        return redirect(url_for('card_management'))
    return render_template('adminCardView.html', cardInfo=card_info)


@app.route('/flowReport', methods=['GET', 'POST'])
def flow_report():
    if not g.admin:
        return redirect(url_for('home'))
    #TODO:implement dates
    flow = query_db('''
select distinct (select Name from Station where StopID=flowIn.startID), flowIn.passIn, flowOut.passOut, flowIn.passIn-flowOut.passOut, revenue.money 
from
(select StopID as startID, count(startTrip.StartsAt) as passIn
from Station 
left join Trip as startTrip
on (Station.StopID=startTrip.StartsAt)
group by startID) as flowIn
join
(select StopID, count(endTrip.EndsAt) as passOut
from Station 
left join Trip as endTrip
on (Station.StopID=endTrip.EndsAt)
group by Station.StopID) as flowOut on (flowIn.startID=flowOut.StopID)
join
(select StartsAt, sum(Tripfare) as money
from Trip
group by Trip.StartsAt) as revenue on (flowIn.startID=revenue.StartsAt)
group by flowIn.startID;
''')

    if request.method == 'POST':
        if request.form['startTime'] and request.form['endTime']:
            #we have both start and end time
            query_statement = '''
select distinct (select Name from Station where StopID=flowIn.startID), flowIn.passIn, flowOut.passOut, flowIn.passIn-flowOut.passOut, revenue.money 
from
(select StopID as startID, count(startTrip.StartsAt) as passIn, StartTime
from Station 
left join Trip as startTrip
on (Station.StopID=startTrip.StartsAt and startTrip.StartTime < "{}" and startTrip.StartTime > "{}")
group by startID) as flowIn
join
(select StopID, count(endTrip.EndsAt) as passOut, StartTime
from Station 
left join Trip as endTrip
on (Station.StopID=endTrip.EndsAt and endTrip.StartTime < "{}" and endTrip.StartTime > "{}")
group by Station.StopID) as flowOut on (flowIn.startID=flowOut.StopID)
join
(select StartsAt, sum(Tripfare) as money
from Trip
where (Trip.StartTime < "{}" and Trip.StartTime > "{}")
group by Trip.StartsAt) as revenue on (flowIn.startID=revenue.StartsAt)
group by flowIn.startID;
'''.format(request.form['endTime'], request.form['startTime'], request.form['endTime'], request.form['startTime'], request.form['endTime'], request.form['startTime'])
            print(query_statement)
            flow = query_db(query_statement)
            return render_template('flowReport.html', flows=flow)
        elif request.form['startTime']:
            #we just have start time
            return render_template('flowReport.html', trips=query_db('''select * from Trip where (BreezecardNum in (select BreezecardNum from Breezecard where BelongsTo = %s)) AND (StartTime > %s);''', [session['user_id'], request.form['startTime']]))
        elif request.form['endTime']:
            #we just have end time
            return render_template('flowReport.html', trips=query_db('''select * from Trip where (BreezecardNum in (select BreezecardNum from Breezecard where BelongsTo = %s)) AND (StartTime < %s);''', [session['user_id'], request.form['endTime']]))

    return render_template('flowReport.html', flows=flow)

@app.route("/stationManagement")
def station_management():
    if not g.admin:
        return redirect(url_for('home'))
    print('''select * from Station order by {} {};'''.format((request.args.get('field')
                                                              if request.args.get('field') else 'Name'), ('asc;' if not request.args.get('asc') else 'desc;')))
    return render_template('stationManagement.html', stations=query_db('''select * from Station order by {} {};'''.format((request.args.get('field') if request.args.get('field') else 'Name'), ('desc' if request.args.get('asc')!='0' else 'asc'))))

@app.route('/stations/<station>', methods=['GET', 'POST'])
def station_view(station):
    if not g.admin:
        return redirect(url_for('home'))
    station_info = query_db('''select * from Station where StopID = %s''', station, one=True)
    if not station_info:
        abort(404)
    intersection = None
    if not station_info[4]:
        #this is a bus so we need the intersection
        intersection = query_db('''select Intersection from BusStationIntersection where StopID=%s''', station, one=True)

    if request.method == 'POST':
        # TODO: validate the input
        post_db('''update Station set EnterFare = %s, ClosedStatus=%s where StopID = %s limit 1''', [(station_info[2] if not request.form['entryFare'] else request.form['entryFare']), (1 if not request.form.get('isOpen') else 0), station])
        return redirect(url_for('station_management'))
    return render_template('stationView.html', station=station_info, intersection=intersection)


@app.route("/createStation", methods=['GET', 'POST'])
def create_station():
    if not g.admin:
        error = 'You must be an admin to view this page'
        return redirect(url_for('home'))
    if request.method == 'POST':
        #TODO: check for valid range of entry fare
        post_db('''insert into Station values (%s, %s, %s, %s, %s);''', [request.form['stopId'], request.form['sName'], request.form['entryFare'], (1 if not request.form.get('isOpen') else 0), (1 if request.form['stationRadio'] == 'train' else 0)])
        if request.form['stationRadio'] == 'bus':
            post_db('''insert into BusStationIntersection values (%s, %s)''', [request.form['stopId'], request.form['nearestIntersection']])
        return redirect(url_for('station_management'))
    return render_template('createStation.html')

@app.route("/welcome")
def welcome():
    return render_template('welcome.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registers the user."""
    if g.user:
        return redirect(url_for('home'))
    error = None
    if request.method == 'POST':
        if not request.form['username']:
            error = 'You have to enter a username'
        elif not request.form['email'] or '@' not in request.form['email'] or not re.search(r'[\w.-]+@[\w.-]+.\w+', request.form['email']):
            error = 'You have to enter a valid email address'
        elif not request.form['password']:
            error = 'You have to enter a password'
        elif request.form['password'] != request.form['password2']:
            error = 'The two passwords do not match'
        elif get_user_id(request.form['username']) is not None:
            error = 'The username is already taken'
        elif query_db('''select Email from Passenger where Email="{}";'''.format(request.form['email']), one=True):
            error = 'That email has already been used'
        elif len(request.form['password']) < 8:
            error = 'Password must be at least eight characters'
        else:
            post_db('''insert into User (Username, Password, IsAdmin) values (%s, %s, FALSE);''', [request.form['username'], generate_password_hash(request.form['password'])])
            post_db('''insert into Passenger (Username, Email) values (%s, %s)''', [request.form['username'], request.form['email']])
            if not request.form['breezeNumber']:
                #need to generate a new breezecard number
                generated_number = random.randint(1000000000000000, 9999999999999999)
                duplicate = query_db('''select BreezecardNum from Breezecard where BreezecardNum = %s''', generated_number)
                #keeps generating a new number until we find one that isn't taken
                while duplicate:
                    generated_number = random.randint(1000000000000000, 9999999999999999)
                    duplicate = query_db('''select BreezecardNum from Breezecard where BreezecardNum = %s''', generated_number)
                post_db('''insert into Breezecard values (%s, 0, %s)''', [generated_number, request.form['username']])
            else:
                # TODO: Add ability to use an existing breeze card
                #they already have a breezecard they want to use
                #need to lookup breezecards and make sure that the number entered is a card that 1. exists and 2. belongs to no one
                # if the card belongs to someone, generate a new card and suspend the old one
                current_holder = query_db('''select BelongsTo from Breezecard where BreezecardNum={}'''.format(
                    request.form['breezeNumber']), one=True)
                if current_holder:
                    current_holder = current_holder[0]
                    post_db('''insert into Conflict values ("{}", {}, "{}")'''.format(
                        request.form['username'], request.form['breezeNumber'], str(datetime.now())))
                    
                    #need to generate a new breezecard number
                    generated_number = random.randint(
                        1000000000000000, 9999999999999999)
                    duplicate = query_db(
                        '''select BreezecardNum from Breezecard where BreezecardNum = %s''', generated_number)
                    #keeps generating a new number until we find one that isn't taken
                    while duplicate:
                        generated_number = random.randint(
                            1000000000000000, 9999999999999999)
                        duplicate = query_db(
                            '''select BreezecardNum from Breezecard where BreezecardNum = %s''', generated_number)
                    post_db('''insert into Breezecard values (%s, 0, %s)''', [
                            generated_number, request.form['username']])

                else:
                    in_db = query_db('''select BreezecardNum from Breezecard where BreezecardNum={}'''.format(
                        request.form['breezeNumber']), one=True)
                    if in_db:
                        post_db('''update Breezecard set BelongsTo="{}" where BreezecardNum={}'''.format(
                            request.form['username'], request.form['breezeNumber']))
                    else:
                        post_db('''insert into Breezecard values ({}, 0.00, "{}")'''.format(
                            request.form['breezeNumber'], request.form['username']))

            flash('You were successfully registered and can login now')
            return redirect(url_for('login'))
    return render_template('register.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Logs the user in."""
    if g.user:
        return redirect(url_for('home'))
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
            if user[2]:
                return redirect(url_for('station_management'))
            return redirect(url_for('home'))
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    """Logs the user out."""
    flash('You were logged out')
    session.pop('user_id', None)
    return redirect(url_for('home'))


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
        connection.commit()
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
