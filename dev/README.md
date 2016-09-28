https://docs.docker.com/engine/swarm/swarm-tutorial/

**_POC Setup_**
```
1. Install and setup Postgres with database --> workers , user --> worker , password --> redcarpet
2. Run redis container
    # docker run -d --name redis redis
3. Run postgres for testing, can't access internal ip from within container
    # docker run --name postgres -e POSTGRES_USER=worker -e POSTGRES_PASSWORD=redcarpet -e POSTGRES_DB=workers -d postgres
4. Run rqscheduler
    # docker run -d --name rqscheduler -d --link redis:redis jkosgei/sandys-rqscheduler
5. Run rqworker
    # docker run -d --name rqworker -d --link postgres:postgres --link redis:redis jkosgei/sandys-rqworker
6. Run python flask app container
    # docker run -d --name flask --link postgres:postgres --link redis:redis jkosgei/sandys-python
7. Run nginx (with https)
    # docker run -d --name nginx --link flask:flask jkosgei/sandys-nginx
8. Get nginx container's ip
    # docker inspect nginx | grep IP 
    # curl -k https://container-ip
```

**_Building_**
```
    Building the flask app
    # cd docker-setup/dev/docker
    # docker build -t jkosgei/sandys-python python
    Building rqworker
    # docker build -t jkosgei/sandys-rqworker rqworker
    Building rqscheduler
    # docker build -t jkosgei/sandys-rqscheduler rqscheduler
    Builing nginx
    # docker build -t jkosgei/sandys-nginx nginx
```

**_Postgres_**
```
    # sudo su - postgres
    # createdb workers
    # psql -d workers
    # CREATE USER worker WITH PASSWORD 'redcarpet';
    # GRANT ALL PRIVILEGES ON DATABASE workers TO worker;
    # sudo apt-get install libpq-dev
    # pip install -r requirements.txt
```

**_Setup_**
```
    flask --> redis
    redis --> rqworker --> postgresql 
    redis --> rqscheduler --> redis
```