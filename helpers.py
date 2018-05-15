import json
from functools import wraps

from flask import session as login_session, make_response, redirect, url_for

from models import User, Category


def equal_session_id(user_id):
    if 'user_id' in login_session:
        return user_id == login_session['user_id']


def get_catalog_info(session):
    catalog = session.query(Category).order_by(Category.name).all()
    return [(c.name, c.id, equal_session_id(c.user_id)) for c in catalog]


def get_category_name(category_id, session):
    return session.query(Category).filter_by(id=category_id).first().name


def get_category(id, session):
    return session.query(Category).filter_by(id=id).first()


def get_user_id(email, session):
    user =  session.query(User).filter_by(email=email).first()
    if user:
        return user.id


def create_user(login_session, session):
    new_user = User(
        name=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture'])

    session.add(new_user)
    session.flush()
    return new_user.id


def verify_item_form(request):
    """Return a tuple of values if succesful, and is not succesful otherwise"""
    item_name = request.form['name'].strip()
    item_description = request.form['description'].strip()
    item_price = request.form['price'].strip()

    all_filled = all([item_name, item_description, item_price])
    if not all_filled:
        return redirect(url_for('new_item_get'))

    if not request.form['category']:
        return json_response("Need a category to add item", 400)

    return item_name, item_description, item_price


def json_response(message, error_code):
    response = make_response(json.dumps(message), error_code)
    response.headers['Content-Type'] = 'application/json'
    return response

def item_to_json(item):
    return {'id': item.id,
            'name': item.name,
            'description': item.description,
            'user_id': item.user_id,
            'category_id': item.category_id}

def item_to_tuple(item):
    d = {'name': item.name,
         'description': item.description,
         'user_id': item.user_id,
         'category_id': item.category_id}
    return (item.id, d)


def ensure_authenticated(f):
    @wraps(f)
    def with_authentication(*args, **kwargs):
        if 'username' not in login_session:
            return redirect(url_for('login'))

        return f(*args, **kwargs)
    return with_authentication


