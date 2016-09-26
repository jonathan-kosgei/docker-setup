https://docs.docker.com/engine/swarm/swarm-tutorial/

Images today;
nginx - custom build
python - custom build, install flask, rscheduler?

java+elasticsearch

**_Postgres_**
    # sudo su - postgres
    # createuser -s --username=postgres $USER
    # createdb workers
    # psql -d workers
    # CREATE USER worker WITH PASSWORD 'redcarpet';
    # GRANT ALL PRIVILEGES ON DATABASE workers TO worker;
    # sudo apt-get install libpq-dev
    # pip install -r requirements.txt