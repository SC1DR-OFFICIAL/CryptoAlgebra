from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from encryption import generate_homomorphic_keypair, serialize_private_key, deserialize_private_key
from phe import paillier
import datetime

app = Flask(__name__)
app.secret_key = 'secret_key_for_session'


# Главная страница
@app.route('/')
def index():
    conn = sqlite3.connect('election.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, end_date FROM poll")  # Получаем дату окончания
    polls = cursor.fetchall()
    conn.close()

    now = datetime.datetime.now().isoformat()  # Текущая дата в ISO-формате
    return render_template('index.html', polls=polls, now=now)


# Регистрация
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])

        conn = sqlite3.connect('election.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO user (username, password_hash) VALUES (?, ?)", (username, password))
        conn.commit()
        conn.close()
        return redirect('/login')

    return render_template('register.html')


# Вход
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('election.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id, password_hash, is_admin FROM user WHERE username=?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['username'] = username
            session['is_admin'] = user[2]
            return redirect('/')

    return render_template('login.html')


# Создание голосования (только для администратора)
@app.route('/admin/create_poll', methods=['GET', 'POST'])
def create_poll():
    if not session.get('is_admin'):
        return "Доступ запрещен", 403

    if request.method == 'POST':
        title = request.form['title']
        end_date = request.form['end_date']
        options = request.form.getlist('options')  # Получаем список вариантов

        if len(options) < 2:
            return "Ошибка: Введите как минимум два варианта ответа."

        public_key, private_key = generate_homomorphic_keypair()

        conn = sqlite3.connect('election.db')
        cursor = conn.cursor()

        # Создаём голосование
        cursor.execute(
            "INSERT INTO poll (title, end_date, public_key_n, public_key_g, private_key) VALUES (?, ?, ?, ?, ?)",
            (title, end_date, str(public_key.n), str(public_key.g), serialize_private_key(private_key)))
        poll_id = cursor.lastrowid  # Получаем ID созданного голосования

        # Добавляем варианты ответа
        for option in options:
            cursor.execute("INSERT INTO poll_options (poll_id, option_text) VALUES (?, ?)", (poll_id, option))

        conn.commit()
        conn.close()

        return redirect('/')

    return render_template('create_poll.html')


# Голосование (с проверкой, голосовал ли пользователь ранее)
@app.route('/poll/<int:poll_id>', methods=['GET', 'POST'])
def vote(poll_id):
    if not session.get('user_id'):
        return redirect('/login')

    user_id = session['user_id']
    conn = sqlite3.connect('election.db')
    cursor = conn.cursor()

    # Получаем информацию о голосовании
    cursor.execute("SELECT title, public_key_n FROM poll WHERE id=?", (poll_id,))
    poll = cursor.fetchone()
    cursor.execute("SELECT id, option_text FROM poll_options WHERE poll_id=?", (poll_id,))
    options = cursor.fetchall()

    if not poll or not options:
        conn.close()
        return "Голосование не найдено", 404

    title, public_key_n = poll

    # Проверяем, голосовал ли пользователь
    cursor.execute("SELECT 1 FROM vote WHERE poll_id=? AND user_id=?", (poll_id, user_id))
    already_voted = cursor.fetchone()

    if already_voted:
        conn.close()
        return redirect(url_for('index'))  # ✅ Если уже голосовал, сразу редирект на главную

    if request.method == 'POST':
        option_id = int(request.form['option'])
        public_key = paillier.PaillierPublicKey(n=int(public_key_n))
        encrypted_vote = public_key.encrypt(1)  # ✅ Голос за вариант (1)

        cursor.execute("INSERT INTO vote (poll_id, user_id, option_id, encrypted_vote) VALUES (?, ?, ?, ?)",
                       (poll_id, user_id, option_id, str(encrypted_vote.ciphertext())))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))  # ✅ После голосования перенаправляем на главную

    conn.close()
    return render_template('vote.html', title=title, poll_id=poll_id, options=options)


# Вывод результатов голосования (для администратора)
@app.route('/poll/<int:poll_id>/results')
def poll_results(poll_id):
    conn = sqlite3.connect('election.db')
    cursor = conn.cursor()

    # Получаем публичный и приватный ключ голосования
    cursor.execute("SELECT public_key_n, private_key FROM poll WHERE id=?", (poll_id,))
    poll = cursor.fetchone()
    if not poll:
        conn.close()
        return "Голосование не найдено", 404

    public_key_n, private_key_str = poll

    # Получаем все варианты ответа
    cursor.execute("SELECT id, option_text FROM poll_options WHERE poll_id=?", (poll_id,))
    options = cursor.fetchall()

    # Восстанавливаем ключи
    public_key = paillier.PaillierPublicKey(n=int(public_key_n))
    private_key = deserialize_private_key(private_key_str, public_key)

    results = {}

    for option_id, option_text in options:
        cursor.execute("SELECT encrypted_vote FROM vote WHERE poll_id=? AND option_id=?", (poll_id, option_id))
        votes = cursor.fetchall()

        if not votes:
            results[option_text] = 0
            continue

        # Восстанавливаем зашифрованные голоса
        encrypted_votes = [paillier.EncryptedNumber(public_key, int(vote[0])) for vote in votes]

        # Считаем сумму голосов
        encrypted_sum = sum(encrypted_votes)

        # Расшифровываем результат
        results[option_text] = private_key.decrypt(encrypted_sum)

    conn.close()
    return render_template('results.html', results=results)



@app.route('/admin/poll/<int:poll_id>/delete', methods=['POST'])
def delete_poll(poll_id):
    if not session.get('is_admin'):
        return "Доступ запрещен", 403

    conn = sqlite3.connect('election.db')
    cursor = conn.cursor()

    # Удаляем голоса, связанные с этим голосованием
    cursor.execute("DELETE FROM vote WHERE poll_id=?", (poll_id,))

    # Удаляем варианты ответа
    cursor.execute("DELETE FROM poll_options WHERE poll_id=?", (poll_id,))

    # Удаляем само голосование
    cursor.execute("DELETE FROM poll WHERE id=?", (poll_id,))

    conn.commit()
    conn.close()

    return redirect('/')


# Выход
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


if __name__ == '__main__':
    app.run(debug=True)
