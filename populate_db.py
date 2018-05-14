from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User

import jinja2

engine = create_engine("sqlite:///restaurantmenu.db")
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

u1 = User(name='u1', email='a@b.com')
u2 = User(name='u2', email='a@c.com')

session.add(u1)
session.add(u2)

r1 = Restaurant(name="r1", user_id=u1.id)
r2 = Restaurant(name="r2", user_id=u2.id)

session.add(r1)
session.add(r2)
# x = session.query(Restaurant).filter_by(name='r1').first()
x = session.query(User).filter_by(name='u1').first()
print(u2.id)
session.commit()

# m1 = MenuItem(name="mi1", course="c1", description="d1", resturant_id=1)
# session.add(m1)
# y = session.query(MenuItem).all()
# print(list(y))
# session.delete(m1)
# session.commit()
# y = session.query(MenuItem).all()
# print(list(y))
