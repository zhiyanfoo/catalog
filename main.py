from app import app
from handlers import login, mainpage, category, item, json_requests # noqa

if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
