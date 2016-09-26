from flask import Flask
from redis import Redis
from rq import Queue
from worker import conn, count_words_at_url
from flask.ext.sqlalchemy import SQLAlchemy

app = Flask(__name__)

db = SQLAlchemy(app)

class Jobs(db.Model):
    job_id = db.Column(db.Integer, primary_key=True)
    results = db.Column(db.String(80), unique=True)

    def __init__(self, results):
        self.results = results

    def __repr__(self):
        return 'Results %r>' % self.results

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://worker:redcarpet@postgres/workers'

db.create_all()

db.session.commit()

q = Queue(connection=conn)

@app.route("/")
def hello():
    conn.set('foo', 'bar')
    return "<h1 style='color:blue'>Hello There!</h1><br>" , conn.get('foo')

@app.route("/queue/<url>")
def queue(url):
    job = q.enqueue(
             count_words_at_url, url)
    return job.get_id()

if __name__ == '__main__':
    app.run(host='0.0.0.0')