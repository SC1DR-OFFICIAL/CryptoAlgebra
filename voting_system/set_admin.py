import sqlite3

conn = sqlite3.connect('election.db')
cursor = conn.cursor()
cursor.execute("UPDATE user SET is_admin = 1 WHERE username = ?", ('Aleksandr',))
conn.commit()
conn.close()

print("Пользователь теперь администратор.")
