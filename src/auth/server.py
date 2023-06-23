import jwt, datetime, os
from flask import Flask, request
from flask_mysqldb import MySQL

server = Flask(__name__)
mysql = MySQL(server)

#config
                        # TODO FYI in the video it uses os.environ.get("MYSQL_HOST") but I think that's wrong/old
server.config["MYSQL_HOST"] = os.environ["MYSQL_HOST"]
server.config["MYSQL_USER"] = os.environ["MYSQL_USER"]
server.config["MYSQL_PASSWORD"] = os.environ["MYSQL_PASSWORD"]
server.config["MYSQL_DB"] = os.environ["MYSQL_DB"]
server.config["MYSQL_PORT"] = os.environ["MYSQL_PORT"]


server.route("/login", methods=["POST"])
def login():
    auth = request.authorization
    if not auth:
        return "Missing credentials", 401, {"WWW-Authenticate": "Basic realm='Login required'"}

    cur = mysql.connection.cursor()
    res = cur.execute("SELECT email, password FROM users WHERE email = %s", [auth.username])
    if res > 0:
        user_row = cur.fetchone()
        email = user_row[0]
        password = user_row[1]

        if auth.username != email or auth.password != password:
            return "Invalid credentials", 401, {"WWW-Authenticate": "Basic realm='Login required'"}
        else:
            return createJWT(auth.username, os.environ.get("JWT_SECRET"), True)
    else:
        return "Invalid credentials", 401, {"WWW-Authenticate": "Basic realm='Login required'"}


server.route("/validate", methods=["POST"])
def validate():
    encoded_jwt = request.headers.get("Authorization")
    if not encoded_jwt:
        return "Missing credentials", 401, {"WWW-Authenticate": "Basic realm='Login required'"}

    encoded_jwt = encoded_jwt.split(" ")[1]
    try:
        decoded = jwt.decode(encoded_jwt, os.environ.get("JWT_SECRET"), algorithms=["HS256"])
    except:
        return "Invalid credentials", 401, {"WWW-Authenticate": "Basic realm='Login required'"}

    return decoded, 200

def createJWT(username, secret, authz):
    return jwt.encode(
        {
            "username": username,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1),
            "iat": datetime.datetime.utcnow(),
            "admin": authz,
        },
        secret,
        algorithm="HS256",
    )


if __name__ == "__main__":
    server.run(host="0.0.0.0", port=5000)