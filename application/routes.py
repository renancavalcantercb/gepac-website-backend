from datetime import datetime
import json
import jwt
from application import app, db, posts
from bson import ObjectId, json_util
from flask import request, redirect, url_for, flash, session, jsonify
from pymongo import DESCENDING
from werkzeug.security import generate_password_hash, check_password_hash

from .utils import utils


@app.route('/news')
def news():
    news = posts.find().sort("date_posted", DESCENDING)
    return json.loads(json_util.dumps(news))


@app.route('/news/<slug>')
def news_detail(slug):
    news = db.posts.find_one({'slug': slug})
    return json.loads(json_util.dumps(news))


@app.route('/register', methods=['GET', 'POST'])
def register_user():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        cpf = request.form['cpf']
        birthdate = request.form['birthdate']
        phone = request.form['phone']
        course = request.form['course']
        liked_posts = []

        error = None
        flash_message = None
        flash_category = None

        if password != confirm_password:
            error = 'As senhas não conferem'

        if error is None:
            user_email = db.stundents.find_one({'email': email})
            if user_email is not None:
                error = f'O email {email} já está cadastrado.'
            else:
                user_cpf = db.stundents.find_one({'cpf': cpf})
                if user_cpf is not None:
                    error = f'O cpf {cpf} já está cadastrado.'
                else:
                    user_phone = db.stundents.find_one({'phone': phone})
                    if user_phone is not None:
                        error = f'O telefone {phone} já está cadastrado.'

        if error is None:
            try:
                db.stundents.insert_one(
                    {'name': name, 'email': email, 'password': generate_password_hash(password), 'cpf': cpf,
                     'birthdate': birthdate, 'phone': phone, 'course': course, 'liked_posts': liked_posts})
                flash_message = f'Usuário {email} cadastrado com sucesso!'
                flash_category = 'success'
                return jsonify({'message': flash_message, 'category': flash_category}, 200)
            except Exception as e:
                error = f"Error occured: {e}"

        if error:
            flash(error, category='danger')
        if flash_message:
            flash(flash_message, category=flash_category)

        return jsonify({'message': error, 'category': 'danger'}, 400)


@app.route('/user/admin')
def admin():
    users = db.users.find()
    stundents = db.stundents.find()
    posts = db.posts.find()
    users_with_roles = []
    students_courses = []
    course_map = {
        '1': 'Selenografia',
        '2': 'Física Estatística',
        '3': 'Python para física'
    }

    for user in users:
        user['admin'] = 'Admin' if user['admin'] else 'User'
        users_with_roles.append(user)

    for stundent in stundents:
        stundent['course'] = course_map.get(stundent['course'], 'Nenhum')
        students_courses.append(stundent)

    return json.loads(json_util.dumps({'users': users_with_roles, 'students': students_courses, 'posts': posts}))


@app.route('/user/admin/create', methods=['POST'])
def create_user():
    email = request.form['email']
    password = request.form['password']
    confirm_password = request.form['confirm_password']
    role = request.form['role']
    admin = True if role == 'admin' else False
    error = None

    if password != confirm_password:
        error = 'As senhas não conferem'
        return jsonify({'message': error, 'category': 'danger'}, 400)

    if error is None:
        try:
            db.users.insert_one({'email': email, 'password': generate_password_hash(password), 'admin': admin})
        except Exception as e:
            error = f"Error occured: {e}"
            flash(error)
        else:
            flash(f'User {email} was successfully registered!', category='success')
            return jsonify({'message': 'Usuário criado com sucesso!', 'category': 'success'}, 200)


@app.route('/subscribed/admin/<user_id>/view', methods=['GET'])
def view_susbcribed(user_id):
    if request.method == 'GET':
        student_info = db.stundents.find_one({'_id': ObjectId(user_id)})
        if student_info is None:
            return jsonify({'message': 'Aluno não encontrado', 'category': 'danger'}, 404)

        student_info_json = {
            'name': student_info['name'],
            'email': student_info['email'],
            'cpf': student_info['cpf'],
            'birthdate': student_info['birthdate'],
            'phone': student_info['phone'],
            'course': student_info['course']
        }
        return json.loads(json_util.dumps(student_info_json))


@app.route('/subscribed/admin/<user_id>/edit', methods=['POST'])
def edit_subscribed(user_id):
    if request.method == 'POST':
        student_info = db.stundents.find_one({'_id': ObjectId(user_id)})

        if student_info['name'] != request.form['name']:
            student_info['name'] = request.form['name']

        if student_info['email'] != request.form['email']:
            student_info['email'] = request.form['email']

        if student_info['birthdate'] != request.form['birthdate']:
            student_info['birthdate'] = request.form['birthdate']

        if student_info['phone'] != request.form['phone']:
            student_info['phone'] = request.form['phone']

        if student_info['course'] != request.form['course']:
            student_info['course'] = request.form['course']

        error = None
        flash_message = None
        flash_category = None

        if error is None:
            try:
                db.stundents.update_one({'_id': ObjectId(user_id)}, {'$set': student_info})
                flash_message = f'Usuário {student_info["email"]} atualizado com sucesso!'
                flash_category = 'success'
                return jsonify({'message': flash_message, 'category': flash_category}, 200)
            except Exception as e:
                error = f"Error occured: {e}"

        if error:
            flash(error, category='danger')
        if flash_message:
            flash(flash_message, category=flash_category)

        return jsonify({'message': error, 'category': 'danger'}, 400)


@app.route('/subscribed/admin/<user_id>/delete', methods=['POST'])
def delete_subscribed(user_id):
    if request.method == 'POST':
        try:
            db.stundents.delete_one({'_id': ObjectId(user_id)})
            flash_message = 'Inscrição excluída com sucesso!'
            flash_category = 'success'
            return jsonify({'message': flash_message, 'category': flash_category}, 200)
        except Exception as e:
            error = f"Error occured: {e}"
            flash(error)
            return jsonify({'message': error, 'category': 'danger'}, 400)


@app.route('/subscribed/admin/search=<search_term>')
def search_subs(search_term):
    if request.method == 'GET':
        try:
            students = db.stundents.find({'$or': [{'name': {'$regex': search_term, '$options': 'i'}},
                                                  {'email': {'$regex': search_term, '$options': 'i'}},
                                                  {'course': {'$regex': search_term, '$options': 'i'}}]})
            return json.loads(json_util.dumps({'students': students}))
        except Exception as e:
            error = f"Error occured: {e}"
            flash(error)
            return jsonify({'message': error, 'category': 'danger'}, 400)


@app.route('/user/admin/search=<search_term>')
def search_users(search_term):
    if request.method == 'GET':
        try:
            users = db.users.find({'$or': [{'name': {'$regex': search_term, '$options': 'i'}},
                                           {'email': {'$regex': search_term, '$options': 'i'}},
                                           {'admin': {'$regex': search_term, '$options': 'i'}}]})
            return json.loads(json_util.dumps({'users': users}))
        except Exception as e:
            error = f"Error occured: {e}"
            flash(error)
            return jsonify({'message': error, 'category': 'danger'}, 400)


@app.route('/news/search=<search_term>')
def search_posts(search_term):
    if request.method == 'GET':
        try:
            posts = db.posts.find({'$or': [{'title': {'$regex': search_term, '$options': 'i'}},
                                           {'content': {'$regex': search_term, '$options': 'i'}},
                                           {'author': {'$regex': search_term, '$options': 'i'}}]})
            return json.loads(json_util.dumps({'posts': posts}))
        except Exception as e:
            error = f"Error occured: {e}"
            flash(error)
            return jsonify({'message': error, 'category': 'danger'}, 400)


@app.route('/user/admin/<user_id>/edit', methods=['POST'])
def edit_user(user_id):
    if request.method == 'POST':
        user = db.users.find_one({'_id': ObjectId(user_id)})
        if request.form['email'] != user['email']:
            user['email'] = request.form['email']

        if request.form.get('admin', False) != user['admin']:
            user['admin'] = request.form.get('admin', False)

        db.users.update_one({'_id': ObjectId(user_id)}, {'$set': user})
        return jsonify({'message': 'Usuário atualizado com sucesso!', 'category': 'success'}, 200)


@app.route('/user/admin/<user_id>/delete', methods=['POST'])
def delete_user(user_id):
    db.users.delete_one({'_id': ObjectId(user_id)})
    return jsonify({'message': 'Usuário deletado com sucesso!', 'category': 'success'}, 200)


@app.route('/news/create', methods=['GET', 'POST'])
def add_news():
    if request.method == 'POST':
        id = utils.generate_id()
        title = request.form['title']
        resume = request.form['resume']
        content = utils.text_to_html(request.form['content'])
        img_url = request.form['img_url']
        slug = utils.slugify(title)
        author = request.form['author']
        date_posted = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        likes = 0
        views = 0

        if title and content and author and date_posted:
            if db.news.find_one({'slug': slug}) or db.news.find_one({'title': title}):
                flash('Title or slug already exists')
                return jsonify({'message': 'Título ou slug já existem', 'category': 'danger'}, 400)

            db.posts.insert_one({
                '_id': id,
                'title': title,
                'resume': resume,
                'slug': slug,
                'content': content,
                'img_url': img_url,
                'author': author,
                'likes': likes,
                'views': views,
                'date_posted': date_posted
            })
            return jsonify({'message': 'Post criado com sucesso!', 'category': 'success'}, 200)

        flash('Please fill all fields')
        return jsonify({'message': 'Por favor, preencha todos os campos', 'category': 'danger'}, 400)
    return jsonify({'message': 'Método não permitido', 'category': 'danger'}, 405)


@app.route('/news/<post_id>/like', methods=['POST'])
def like_news(post_id):
    if request.method == 'POST':
        student_id = request.form['student_id']
        student = db.stundents.find_one({'_id': ObjectId(student_id)})
        if student is None:
            return jsonify({'message': 'Aluno não encontrado', 'category': 'danger'}, 400)

        if post_id not in student['liked_posts']:
            db.students.update_one({'_id': ObjectId(student_id)}, {'$push': {'liked_posts': post_id}})
            db.posts.update_one({'_id': post_id}, {'$inc': {'likes': 1}})
            return jsonify({'message': 'Post curtido com sucesso!', 'category': 'success'}, 200)
        else:
            db.students.update_one({'_id': ObjectId(student_id)}, {'$pull': {'liked_posts': post_id}})
            db.posts.update_one({'_id': post_id}, {'$inc': {'likes': -1}})
            return jsonify({'message': 'Post descurtido com sucesso!', 'category': 'success'}, 200)


@app.route('/news/<post_id>/views', methods=['POST'])
def view_news(post_id):
    if request.method == 'POST':
        post = db.posts.find_one({'_id': post_id})
        if post:
            views = post.get('views', 0) + 1
            db.posts.update_one({'_id': post_id}, {'$set': {'views': views}})
            return jsonify({'message': 'Post visualizado com sucesso!', 'category': 'success'}, 200)
        else:
            return jsonify({'message': 'Post não encontrado', 'category': 'error'}, 404)


@app.route('/news/<post_id>/edit', methods=['GET', 'POST'])
def edit_news(post_id):
    if request.method == 'POST':
        news = db.posts.find_one({'_id': post_id})
        if request.form['title'] != news['title']:
            news['title'] = request.form['title']
            news['slug'] = utils.slugify(request.form['title'])
        elif request.form['resume'] != news['resume']:
            news['resume'] = request.form['resume']
        elif request.form['content'] != news['content']:
            news['content'] = utils.text_to_html(request.form['content'])
        elif request.form['img_url'] != news['img_url']:
            news['img_url'] = request.form['img_url']
        elif request.form['author'] != news['author']:
            news['author'] = request.form['author']

        db.posts.update_one({'_id': post_id}, {'$set': news})
        return jsonify({'message': 'Post editado com sucesso!', 'category': 'success'}, 200)


@app.route('/news/<post_id>/delete', methods=['POST'])
def delete_news(post_id):
    db.posts.delete_one({'_id': post_id})
    return jsonify({'message': 'Post deletado com sucesso!', 'category': 'success'}, 200)


@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        error = None

        user = db.stundents.find_one({'email': email})
        if user is None:
            error = f'{email} não cadastrado.'
            return jsonify({'message': error, 'category': 'danger'}, 404)

        if error is None:
            if check_password_hash(user['password'], password):
                session['logged_in'] = True
                session['name'] = user['name']

                payload = {
                    'id': str(user['_id']),
                    'name': user['name'],
                    'email': user['email']
                }

                jwt_token = jwt.encode(payload, 'secret_key', algorithm='HS256')
                return jsonify({'message': 'Usuário logado com sucesso!', 'category': 'success',
                                'token': jwt_token}, 200)

            else:
                error = 'Usuário ou senha incorretos.'
                return jsonify({'message': error, 'category': 'danger'}, 403)


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session['logged_in'] = False
    session['email'] = None
    session['name'] = None
    session.clear()
    return jsonify({'message': 'Logout realizado com sucesso!', 'category': 'success'}, 200)


@app.errorhandler(404)
def page_not_found(e):
    return jsonify({'message': 'Página não encontrada', 'category': 'danger'}, 404)
