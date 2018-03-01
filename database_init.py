from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item
import json

# Setting the database engine to communicate with
engine = create_engine('sqlite:///onlineshop.db')
# Bind the engine to base class
Base.metadata.bind = engine
# Establish connection betwwen code and database
DBSession = sessionmaker(bind=engine)
# Finally create session object
session = DBSession()

# Remove all data if already exists
session.query(User).delete()
session.query(Category).delete()
session.query(Item).delete()

# Load data JSON file
data = json.load(open('data.json'))
users = data['data_list'][0]['users_list']
categories = data['data_list'][1]['categories_list']
items = data['data_list'][2]['items_list']

# Load User data
for entry in users:
    user = User(username=entry['username'], email=entry['email'],
                picture=entry['picture'])
    session.add(user)

# Commit users changes to database
session.commit()

# Load Category data
for entry in categories:
    category = Category(name=entry['name'], user_id=entry['user_id'],
                        picture=entry['picture'])
    session.add(category)

# Commit categories changes to database
session.commit()

# Load Item data
for entry in items:
    item = Item(name=entry['name'], picture=entry['picture'],
                description=entry['description'],
                price=entry['price'],
                category_id=entry['category_id'],
                user_id=entry['user_id'])
    session.add(item)

# Commit categories changes to database
session.commit()

print 'Finished populating database...'
