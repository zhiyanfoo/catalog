from models import Category, Item
from helpers import json_response, item_to_json, item_to_tuple
from app import app
from session import session_scope


@app.route('/category/<int:category_id>/item/<int:item_id>/json/')
def item_get_json(category_id, item_id):
    with session_scope() as session:
        item = session.query(Item).filter_by(id=item_id).first()
        if item:
            return json_response(item_to_json(item), 200)

        json_response({"error": "item does not exist"}, 404)


@app.route('/json')
def catalog_get_json():
    with session_scope() as session:
        catalog = session.query(Category).all()
        category_list = []
        for category in catalog:
            items = (session.query(Item)
                     .filter_by(catagory_id=category.id).all())
            d = {'id': category.id,
                 'name': category.name,
                 'items': dict(map(item_to_tuple, items))}
            category_list.append(d)

        return json_response(category_list, 200)
