from flask import Flask, render_template, request, make_response, flash
from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item
import random, string, json, httplib2, requests

app = Flask(__name__)

engine = create_engine('sqlite:///onlineshop.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Online shop"

def check_user_id(email):
    user = session.query(User).filter_by(email=email).first()
    if user is not None:
        return user.id
    return None


def create_user(login_session):
    user = User(username=login_session['username'], email=login_session['email'],
                picture=login_session['picture'])
    session.add(user)
    session.commit()


# Create anti-forgery state token
@app.route('/login/')
def show_login():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # Create the user if doesn't exist
    user_id = check_user_id(login_session['email'])
    if user_id is None:
        create_user(login_session)
        user_id = check_user_id(login_session['email'])
    login_session['user_id'] = user_id

    output = [login_session['username'], login_session['picture']]
    print "done!"
    return json.dumps(output)


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/')
@app.route('/home')
def shop_categories():
    categories = session.query(Category).all()
    items = session.query(Item).all()
    return render_template('home.html', categories=categories, items=items)


@app.route('/catalog/<path:category_name>/items/')
def show_category(category_name):
    category = session.query(Category).filter_by(name=category_name).first()
    items = session.query(Item).filter_by(category_id=category.id)
    return render_template('category.html', items=items, category=category)


@app.route('/catalog/<path:category_name>/<path:item_name>/')
def show_item(category_name, item_name):
    category = session.query(Category).filter_by(name=category_name).first()
    item = session.query(Item).filter_by(category_id=category.id, name=item_name).first()
    if 'username' not in login_session:
        return render_template('item.html', owner=False, item=item)
    else:
        return render_template('item.html', owner=True, item=item)


if __name__ == '__main__':
    app.secret_key = 'secret_key'
    app.debug = True
    app.run(host='localhost', port=8000)