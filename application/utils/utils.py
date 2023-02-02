from functools import wraps
import re
import markdown

from bson import ObjectId
from flask import redirect, url_for, session


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def is_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin'):
            return redirect(url_for('index'))
        return f(*args, **kwargs)

    return decorated_function


def generate_id():
    return str(ObjectId())


def text_to_html(text):
    return markdown.markdown(text)


def slugify(title):
    return re.sub(r"[^\w\s]", '', title).replace(" ", "-").lower()
