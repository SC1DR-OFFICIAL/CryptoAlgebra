from flask import Flask, render_template, request, redirect, session
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
    cursor.execute("SELECT id, title FROM poll WHERE end_date >= ?", (datetime.datetime.now().isoformat(),))
    polls = cursor.fetchall()
    conn.close()
    return render_template('index.html', polls=polls)


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
        public_key, private_key = generate_homomorphic_keypair()

        conn = sqlite3.connect('election.db')
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO poll (title, end_date, public_key_n, public_key_g, private_key) VALUES (?, ?, ?, ?, ?)",
            (title, end_date, str(public_key.n), str(public_key.g), serialize_private_key(private_key)))  # Исправлено!
        conn.commit()
        conn.close()

        return redirect('/')

    return render_template('create_poll.html')


# Голосование
@app.route('/poll/<int:poll_id>', methods=['GET', 'POST'])
def vote(poll_id):
    if not session.get('user_id'):
        return redirect('/login')

    conn = sqlite3.connect('election.db')
    cursor = conn.cursor()
    cursor.execute("SELECT title, public_key_n FROM poll WHERE id=?", (poll_id,))
    poll = cursor.fetchone()

    if not poll:
        conn.close()
        return "Голосование не найдено", 404

    if request.method == 'POST':
        choice = int(request.form['choice'])
        public_key = paillier.PaillierPublicKey(n=int(poll[1]))  # Преобразуем обратно в int
        encrypted_vote = public_key.encrypt(choice).ciphertext

        cursor.execute("INSERT INTO vote (poll_id, user_id, encrypted_vote) VALUES (?, ?, ?)",
                       (poll_id, session['user_id'], str(encrypted_vote)))  # Сохраняем как строку
        conn.commit()
        conn.close()
        return "Голос принят"

    return render_template('vote.html', title=poll[0], poll_id=poll_id)


# Вывод результатов голосования (для администратора)
@app.route('/admin/poll/<int:poll_id>/results')
def poll_results(poll_id):
    if not session.get('is_admin'):
        return "Доступ запрещен", 403

    conn = sqlite3.connect('election.db')
    cursor = conn.cursor()
    cursor.execute("SELECT public_key_n, private_key FROM poll WHERE id=?", (poll_id,))
    poll = cursor.fetchone()

    if not poll:
        conn.close()
        return "Голосование не найдено", 404

    public_key = paillier.PaillierPublicKey(n=int(poll[0]))  # Преобразуем обратно в int
    private_key = deserialize_private_key(poll[1], public_key)

    cursor.execute("SELECT encrypted_vote FROM vote WHERE poll_id=?", (poll_id,))
    votes = cursor.fetchall()
    conn.close()

    if not votes:
        return "Голосов пока нет"

    encrypted_sum = sum([paillier.EncryptedNumber(public_key, int(vote[0])) for vote in votes])
    result = private_key.decrypt(encrypted_sum)

    return f"Результат: {result} голосов 'За'"


# Выход
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


if __name__ == '__main__':
    app.run(debug=True)
