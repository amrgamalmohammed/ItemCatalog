from flask import (Flask,
                   render_template,
                   request,
                   make_response,
                   flash, redirect,
                   url_for,
                   jsonify)
from flask import session as login_session
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from database_setup import Base, User, Category, Item
import random
import string
import json
import httplib2
import requests


app = Flask(__name__)
# Setting the database engine to communicate with
engine = create_engine('sqlite:///onlineshop.db')
# Bind the engine to base class
Base.metadata.bind = engine
# Establish connection betwwen code and database
DBSession = sessionmaker(bind=engine)
# Finally create session object
session = DBSession()

# Load client_secrets for further authentication
CLIENT_ID = json.loads(open('client_secrets.json', 'r')
                       .read())['web']['client_id']
APPLICATION_NAME = "Online shop"


# Helper method: Creates a user into the database
def create_user(login_session):
    new_user = User(username=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(new_user)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


# Helper method: Gets user's id based on the email
def get_user_ID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# Create anti-forgery state token
@app.route('/login/')
def show_login():
    state = ''.join(random.choice(
        string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# Render logout page
@app.route('/logout/')
def show_logout():
    return render_template('logout.html')


# Handle google login
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
        response = make_response(json.dumps(
            'Current user is already connected.'), 200)
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
    user_id = get_user_ID(login_session['email'])
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    output = [login_session['username'], login_session['picture']]
    flash('Welcome '+login_session['username']+'!')
    return json.dumps(output)


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Send disconnection request to google
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s'\
          % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    # If successful delete all stored records
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        flash('Successfully logged out')
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# Render main home page
@app.route('/')
@app.route('/home')
def shop_categories():
    categories = session.query(Category).all()
    return render_template('home.html', categories=categories)


# Show items in a category
@app.route('/catalog/<path:category_name>/items/')
def show_category(category_name):
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(Item).filter_by(category_id=category.id)
    # Render category and send info about ownership
    if 'username' not in login_session or \
            login_session['user_id'] != category.user_id:
        return render_template('category.html',
                               owner=False, items=items, category=category)
    else:
        return render_template('category.html',
                               owner=True, items=items, category=category)


# Show an item's details
@app.route('/catalog/<path:category_name>/<path:item_name>/')
def show_item(category_name, item_name):
    category = session.query(Category).filter_by(name=category_name).one()
    item = session.query(Item).filter_by(category_id=category.id,
                                         name=item_name).one()
    # Render item and send info about ownership
    if 'username' not in login_session or \
            login_session['user_id'] != item.user_id:
        return render_template('item.html', owner=False, item=item)
    else:
        return render_template('item.html', owner=True,
                               category=category, item=item)


# Show form to add category and handle posting the form
@app.route('/catalog/add/', methods=['GET', 'POST'])
def add_category():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        # Validate form fields
        name = request.form['category-name']
        picture = request.form['category-picture']
        if name is not u'':
            if picture is u'':
                picture = '/static/img/600x300.png'
            category = Category(name=name, picture=picture,
                                user_id=login_session['user_id'])
            session.add(category)
            session.commit()
            flash('New category %s successfully created' % category.name)
        else:
            flash('Category\'s name can not be empty')
        return redirect('/')
    else:
        return render_template('addcategory.html')


# Show form to add item and handle posting the form
@app.route('/catalog/<path:category_name>/add/', methods=['GET', 'POST'])
def add_item(category_name):
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        category = session.query(Category).filter_by(name=category_name).one()
        if category.user_id == login_session['user_id']:
            # Validate form fields
            name = request.form['item-name']
            picture = request.form['item-picture']
            description = request.form['item-description']
            price = request.form['item-price']
            if name is not u'' and description is not u'':
                if picture is u'':
                    picture = '/static/img/300x300.jpg'
                item = Item(name=name, picture=picture,
                            description=description, price=price,
                            category_id=category.id,
                            user_id=login_session['user_id'])
                session.add(item)
                session.commit()
                flash('New item %s successfully created' % item.name)
            else:
                flash('Item\'s name and description can not be empty')
        else:
            flash('Sorry you are not the owner of this category!')
        return redirect(url_for('show_category', category_name=category_name))
    else:
        return render_template('additem.html', category_name=category_name)


# Show form to edit category and handle posting the form
@app.route('/catalog/<path:category_name>/edit/', methods=['GET', 'POST'])
def edit_category(category_name):
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        category = session.query(Category).filter_by(name=category_name).one()
        if category.user_id == login_session['user_id']:
            # Validate form fields
            name = request.form['category-name']
            picture = request.form['category-picture']
            if name is not u'':
                category.name = name
            if picture is not u'':
                category.picture = picture
            session.add(category)
            session.commit()
            flash('Edited category %s successfully' % category.name)
        else:
            flash('Sorry you are not the owner of this category!')
        return redirect(url_for('show_category',
                                category_name=category.name))
    else:
        return render_template('editcategory.html',
                               category_name=category_name)


# Show form to edit item and handle posting the form
@app.route('/catalog/<path:category_name>/<path:item_name>/edit/',
           methods=['GET', 'POST'])
def edit_item(category_name, item_name):
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        item = session.query(Item).filter_by(name=item_name).one()
        if item.user_id == login_session['user_id']:
            # Validate form fields
            name = request.form['item-name']
            picture = request.form['item-picture']
            price = request.form['item-price']
            description = request.form['item-description']
            if name is not u'':
                item.name = name
            if picture is not u'':
                item.picture = picture
            if description is not u'':
                item.description = description
            if price is not u'':
                item.price = price
            session.add(item)
            session.commit()
            flash('Edited item %s successfully' % item.name)
        else:
            flash('Sorry you are not the owner of this item!')
        return redirect(url_for('show_item', category_name=category_name,
                                item_name=item.name))
    else:
        return render_template('edititem.html', category_name=category_name,
                               item_name=item_name)


# Show form to delete category and handle posting the form
@app.route('/catalog/<path:category_name>/delete/', methods=['GET', 'POST'])
def delete_category(category_name):
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        category = session.query(Category).filter_by(name=category_name).one()
        # Check if the owner is deleting
        if category.user_id == login_session['user_id']:
            session.delete(category)
            session.commit()
            flash('deleted category %s successfully' % category_name)
        else:
            flash('Sorry you are not the owner of this category!')
        return redirect('/')
    else:
        return render_template('deletecategory.html',
                               category_name=category_name)


# Show form to edit item and handle posting the form
@app.route('/catalog/<path:category_name>/<path:item_name>/delete/',
           methods=['GET', 'POST'])
def delete_item(category_name, item_name):
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        item = session.query(Item).filter_by(name=item_name).one()
        # Check if the owner is deleting
        if item.user_id == login_session['user_id']:
            session.delete(item)
            session.commit()
            flash('deleted item %s successfully' % item_name)
        else:
            flash('Sorry you are not the owner of this item!')
        return redirect(url_for('show_category', category_name=category_name))
    else:
        return render_template('deleteitem.html', category_name=category_name,
                               item_name=item_name)


# JSON API call to show all categories
@app.route('/catalog/api/categories')
def categories_api():
    try:
        categories = session.query(Category).all()
        serialized = []
        # Serialize category objects
        for category in categories:
            serialized.append(category.serialize)
        return jsonify(categories=serialized)
    except NoResultFound:
        return jsonify({'error': 'No result found'})


# JSON API call to show items in category
@app.route('/catalog/api/categories/<path:category_name>')
def category_api(category_name):
    try:
        category = session.query(Category).filter_by(name=category_name).one()
        items = session.query(Item).filter_by(category_id=category.id).all()
        serialized = []
        # Serialize item objects
        for item in items:
            serialized.append(item.serialize)
        return jsonify(items=serialized)
    except NoResultFound:
        return jsonify({'error': 'No result found'})


# JSON API call to show specific item
@app.route('/catalog/api/items/<path:category_name>/<path:item_name>')
def item_api(category_name, item_name):
    try:
        category = session.query(Category).filter_by(name=category_name).one()
        item = session.query(Item).filter_by(
            category_id=category.id, name=item_name).one()
        # Serialize item object
        return jsonify(item.serialize)
    except NoResultFound:
        return jsonify({'error': 'No result found'})


# JSON API call to show all store information
@app.route('/catalog/api/catalog')
def catalog_api():
    # Protected JSON API call
    if 'username' in login_session:
        try:
            categories = session.query(Category)\
                .order_by(asc(Category.id)).all()
            serialized = []
            # Serialize all category items
            for category in categories:
                result = {'category': category.serialize, 'items': []}
                items = session.query(Item).filter_by(
                    category_id=category.id).all()
                for item in items:
                    result['items'].append(item.serialize)
                serialized.append(result)

            return jsonify(result=serialized)
        except NoResultFound:
            return jsonify({'error': 'No result found'})
    else:
        return jsonify({'error': 'This a protected call please login first'})


# JSON API call to show all items
@app.route('/catalog/api/items')
def items_api():
    # Protected JSON API call
    if 'username' in login_session:
        try:
            items = session.query(Item).all()
            serialized = []
            for item in items:
                serialized.append(item.serialize)
            return jsonify(items=serialized)
        except NoResultFound:
            return jsonify({'error': 'No result found'})
    else:
        return jsonify({'error': 'This a protected call please login first'})


# Main call
if __name__ == '__main__':
    app.secret_key = 'secret_key'
    app.debug = True
    app.run(host='localhost', port=8000)
