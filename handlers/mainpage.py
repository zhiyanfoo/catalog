from models import Item

from flask import render_template
from sqlalchemy import desc

from app import app
from session import session_scope
from helpers import get_catalog_info, get_category_name


@app.route('/')
def mainpage():
    with session_scope() as session:
        catalog_info = get_catalog_info(session)
        latest_items = (session.query(Item)
                        .order_by(desc(Item.created))
                        .limit(6)
                        .all())
        latest_items_info = [
            (item, get_category_name(item.category_id, session))
            for item in latest_items]
        return render_template("mainpage.html", catalog_info=catalog_info,
                               latest_items_info=latest_items_info)
