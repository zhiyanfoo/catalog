from sqlalchemy import desc
from flask import (render_template, redirect, url_for, request,
                   session as login_session)


from app import app
from models import Category, Item
from helpers import (equal_session_id, get_catalog_info, get_category,
                     json_response, ensure_authenticated,
                     get_category_from_name)
from session import session_scope


@app.route('/category/<int:category_id>/')
def category(category_id):
    with session_scope() as session:
        catalog_info = get_catalog_info(session)
        current_category = (session.query(Category)
                            .filter_by(id=category_id).first())

        if not current_category:
            return json_response("invalid category", 404)

        items = (session.query(Item)
                 .filter_by(category_id=category_id)
                 .order_by(desc(Item.created))
                 .all())
        items_info = [(item, equal_session_id(item.user_id)) for item in items]
        return render_template("category.html",
                               current_category=current_category,
                               catalog_info=catalog_info,
                               items_info=items_info)


@app.route('/category/new', methods=['Get'])
@ensure_authenticated
def new_category_get():
    return render_template('new_category.html')


@app.route('/category/new', methods=['Post'])
@ensure_authenticated
def new_category_post():
    category_name = request.form['name'].strip()
    if not category_name:
        return redirect(url_for('new_category_get'))

    with session_scope() as session:
        if get_category_from_name(category_name, session):
            return json_response("category name already exits", 400)

        session.add(
            Category(name=request.form['name'],
                     user_id=login_session['user_id']))

    return redirect(url_for('mainpage'))


@app.route('/category/<int:category_id>/edit/', methods=['Get'])
@ensure_authenticated
def edit_category_get(category_id):
    with session_scope() as session:
        category = get_category(category_id, session)
        if not category or not equal_session_id(category.user_id):
            return redirect(url_for('login'))

        return render_template("edit_category.html", id=category_id,
                               name=category.name)


@app.route('/category/<int:category_id>/edit/', methods=['Post'])
@ensure_authenticated
def edit_category_post(category_id):
    with session_scope() as session:
        category = get_category(category_id, session)
        if not category or not equal_session_id(category.user_id):
            return redirect(url_for('login'))

        new_category_name = request.form['name'].strip()

        if not new_category_name:
            return redirect(url_for('edit_category'))

        duplicate = (category.name != new_category_name
                     and get_category_from_name(new_category_name, session))

        if duplicate:
            return json_response("category name already exits", 400)

        category.name = new_category_name
        return redirect(url_for('mainpage'))


@app.route('/category/<int:category_id>/delete/')
@ensure_authenticated
def delete_category_get(category_id):
    with session_scope() as session:
        category = get_category(category_id, session)
        if not category or not equal_session_id(category.user_id):
            return redirect(url_for('login'))

        return render_template("confirm_delete.html")


@app.route('/category/<int:category_id>/delete/', methods=['Post'])
@ensure_authenticated
def delete_category_post(category_id):
    with session_scope() as session:
        category = get_category(category_id, session)
        if not category or not equal_session_id(category.user_id):
            return redirect(url_for('login'))

        items = (session.query(Item)
                 .filter_by(category_id=category.id)
                 .all())

        for item in items:
            session.delete(item)

        session.delete(category)
        return redirect(url_for('mainpage'))
