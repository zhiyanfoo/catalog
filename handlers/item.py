from flask import (render_template, redirect, url_for, request,
                   session as login_session)

from models import Category, Item
from helpers import (equal_session_id, get_catalog_info, json_response,
                     ensure_authenticated, verify_item_form)
from app import app
from session import session_scope


@app.route('/category/<int:category_id>/item/new')
@app.route('/category/item/new')
@ensure_authenticated
def new_item_get(category_id=None):
    with session_scope() as session:
        catalog_info = get_catalog_info(session)
        if not catalog_info:
            return json_response("Add Category first", 400)

        return render_template("new_item.html",
                               catalog_info=catalog_info)


@app.route('/category/item/new', methods=['Post'])
@ensure_authenticated
def new_item_post():
    items_or_response = verify_item_form(request)
    if not isinstance(items_or_response, tuple):
        return items_or_response

    item_name, item_description, item_price = items_or_response

    with session_scope() as session:
        category = (session.query(Category)
                    .filter_by(name=request.form['category']).first())

        session.add(
            Item(name=item_name,
                 description=item_description,
                 price=item_price,
                 user_id=login_session['user_id'],
                 category_id=category.id))

        return redirect(url_for('category', category_id=category.id))


@app.route('/category/<int:category_id>/item/<int:item_id>/delete/')
@ensure_authenticated
def delete_item_get(category_id, item_id):
    with session_scope() as session:
        item = session.query(Item).filter_by(id=item_id).first()
        if not item or not equal_session_id(item.user_id):
            return redirect('/login')

        session.delete(item)
        return redirect(url_for('category', category_id=category_id))


@app.route('/category/<int:category_id>/item/<int:item_id>/edit/')
@ensure_authenticated
def edit_item_get(category_id, item_id):
    with session_scope() as session:
        item = session.query(Item).filter_by(id=item_id).first()
        if not item or not equal_session_id(item.user_id):
            return redirect('/login')

        catalog_info = get_catalog_info(session)
        return render_template("edit_item.html",
                               catalog_info=catalog_info,
                               item=item)


@app.route('/category/<int:category_id>/item/<int:item_id>/edit/',
           methods=['Post'])
@ensure_authenticated
def edit_item_post(category_id, item_id):
    with session_scope() as session:
        item = session.query(Item).filter_by(id=item_id).first()
        if not item:
            return json_response("invalid id", 404)

        if not equal_session_id(item.user_id):
            return redirect('/login')

        items_or_response = verify_item_form(request)
        if not isinstance(items_or_response, tuple):
            return items_or_response

        item.name, item.description, item.price = items_or_response
        return redirect(url_for('category', category_id=category_id))
