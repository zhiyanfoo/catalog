import json

from flask import session as login_session, make_response

from database_setup import User, Catalog


def equal_session_id(user_id):
    if 'user_id' in login_session:
        return user_id == login_session['user_id']


def get_catalog_info(session):
    catalog = session.query(Catalog).order_by(Catalog.name).all()
    return [(c.name, c.id, equal_session_id(c.user_id)) for c in catalog]


def get_catalog_name(catalog_id, session):
    return session.query(Catalog).filter_by(id=catalog_id).first().name


def get_catalog(id, session):
    return session.query(Catalog).filter_by(id=id).first()


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


def nocache(view):
    @wraps(view)
    def no_cache(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Last-Modified'] = datetime.now()
        response.headers['Cache-Control'] = ('no-store, no-cache,'
                                             ' must-revalidate, post-check=0,'
                                             ' pre-check=0, max-age=0')
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response

    return update_wrapper(no_cache, view)


def json_response(message, error_code):
    response = make_response(json.dumps(message), error_code)
    response.headers['Content-Type'] = 'application/json'
    return response
