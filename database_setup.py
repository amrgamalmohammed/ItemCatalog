import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

engine = create_engine("sqlite:///onlineshop.db")

class User(Base):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True)
    username = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))

class Category(Base):
    __tablename__ = "category"
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey("user.id"))
    user = relationship(User)

class Item(Base):
    __tablename__ = "item"
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    picture = Column(String(250))
    description = Column(String(250), nullable=False)
    category_id = Column(Integer, ForeignKey("category.id"))
    user_id = Column(Integer, ForeignKey("user.id"))
    category = relationship(Category)
    user = relationship(User)

Base.metadata.create_all(engine)