# Item Catalog

- This project is an online shop website that enables users to view a catalog of existing categories and view items within a category.
- Users can login using Google accounts in order to add, edit or delete categories and items.
- Using ```SQLAlchemy``` to interact with a backend database that holds all info about the store and its users.
- Using ```Flask``` framework to handle page interacting, server calls and ```JSON``` API endpoints.

## Installation

- The project is implemented in ```Python 2.7```.
- You will need some libraries to run the scripts like ```flask```,```sqlalchemy``` and ```oauth2client```.
- To setup database schema run ```database_setup.py```.
- To populate database with some predefined data run ```database_init.py```.
- You can provide your own data to populate with by adding to ```data.json``` file.
- To run the app run ```application.py``` and head to ```localhost:8000``` in your browser.

## Usage

Users can navigate through the web app using the provided buttons for actions like view, add, edit and delete.

### For non-authenticated users

- You can view home page, browse categories and view categories' items.
- You can also use most of the ```JSON``` API calls (more on that later).

### For authenticated users

- You can add, edit and delete categories and items if you are the owner of that category or item.
- You have full access to all ```JSON``` API calls.

## JSON API

### Public access

- Use ```/catalog/api/categories``` to get all categories.
- Use ```/catalog/api/categories/<category_name>``` to get information about items in that category.
- Use ```/catalog/api/items/<category_name>/<item_name>``` to get information about an item in a category.

### Private (logged in) users

- Use ```/catalog/api/catalog``` to show all store information including all categories and items.
- Use ```/catalog/api/items``` to show all items in store.

## Contributors

- amrgamalmohammed