from sqlalchemy import Column, ForeignKey, Integer, String, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

# Database setup
Base = declarative_base()
# Setting the database engine to communicate with
engine = create_engine("sqlite:///onlineshop.db")


# User's table
class User(Base):

    __tablename__ = "user"
    id = Column(Integer, primary_key=True)
    username = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


# Category's table
class Category(Base):

    __tablename__ = "category"
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    picture = Column(String(250))
    user_id = Column(Integer, ForeignKey("user.id"))
    user = relationship(User)

    # Add a decorator property to serialize data from database
    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'picture': self.picture
        }


# Item's table
class Item(Base):

    __tablename__ = "item"
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    picture = Column(String(250))
    description = Column(String(250), nullable=False)
    price = Column(Float, nullable=False)
    category_id = Column(Integer, ForeignKey("category.id"))
    user_id = Column(Integer, ForeignKey("user.id"))
    category = relationship(Category)
    user = relationship(User)

    # Add a decorator property to serialize data from database
    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'picture': self.picture,
            'description': self.description,
            'price': self.price
        }


Base.metadata.create_all(engine)
