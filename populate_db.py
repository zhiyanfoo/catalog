from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Catalog, Item, User

import jinja2

engine = create_engine("sqlite:///catalog.db")
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

u1 = User(name='u1', email='a@b.com')
u2 = User(name='u2', email='a@c.com')

session.add(u1)
session.add(u2)

r1 = Catalog(name="r1", user_id=u1.id)
r2 = Catalog(name="r2", user_id=u2.id)

session.add(r1)
session.add(r2)
# x = session.query(Catalog).filter_by(name='r1').first()
x = session.query(User).filter_by(name='u1').first()
print(u2.id)
session.commit()

m1 = Item(name="mi1", course="c1", price="432.2", description="d1", catalog_id=1, user_id=1)
# session.add(m1)
# y = session.query(Item).all()
# print(list(y))
# session.delete(m1)
# session.commit()
# y = session.query(Item).all()
# print(list(y))
