# Web server
from flask import Flask, render_template, request, jsonify, session

# Socket io
from flask_socketio import SocketIO, emit, join_room, leave_room
import mysql.connector
from datetime import datetime
import logging
import threading
from packet_capture import start_capture

# Configure logging
logging.basicConfig(
    filename="app.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

app = Flask(__name__, template_folder="templates")
app.config["SECRET_KEY"] = "jkhkjwehw"
socketio = SocketIO(app, cors_allowed_origins="*")

live_users = []

# Database configuration
db_config = {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "root",
    "password": "password",  # TODO Change this to root
    "database": "secure_messaging",
}

user_public_keys = {}


# Store connected users
users = {}


def init_db():
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()

    # Create messages table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS messages (
            id INT AUTO_INCREMENT PRIMARY KEY,
            sender VARCHAR(255) NOT NULL,
            content TEXT NOT NULL,
            message_type VARCHAR(50) NOT NULL,
            recipient VARCHAR(255),
            timestamp DATETIME NOT NULL
        )
    """
    )

    # Create users table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL
        )
    """
    )

    conn.commit()
    cursor.close()
    conn.close()


@app.route("/")
def index():
    if "username" not in session:
        return render_template("login.html")
    return render_template("chat.html", username=session["username"])


@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE username = %s AND password = %s",
        (username, password),
    )
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user:
        return jsonify({"success": False})

    session["username"] = username
    return jsonify({"success": True})


@app.route("/logout")
def logout():
    session.pop("username", None)
    return jsonify({"success": True})


@app.route("/messages")
def view_messages():
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    # Get messages
    cursor.execute(
        """
        SELECT sender, content, message_type, recipient, timestamp 
        FROM messages 
        ORDER BY timestamp DESC
    """
    )
    messages = cursor.fetchall()

    # Get statistics
    cursor.execute("SELECT COUNT(DISTINCT sender) as unique_users FROM messages")
    unique_users = cursor.fetchone()["unique_users"]

    cursor.execute(
        """
        SELECT message_type, COUNT(*) as count
        FROM messages 
        GROUP BY message_type
    """
    )
    message_types = {row["message_type"]: row["count"] for row in cursor.fetchall()}

    statistics = {
        "total_messages": len(messages),
        "unique_users": unique_users,
        "message_types": message_types,
    }

    cursor.close()
    conn.close()

    return render_template("messages.html", messages=messages, statistics=statistics)


@app.route("/api/messages", methods=["GET"])
def get_messages_api():
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    # Get messages
    cursor.execute(
        """
        SELECT id, sender, content, message_type, recipient, timestamp 
        FROM messages 
        ORDER BY timestamp DESC
    """
    )
    messages = cursor.fetchall()

    # Convert datetime objects to string for JSON serialization
    for message in messages:
        message["timestamp"] = message["timestamp"].strftime("%Y-%m-%d %H:%M:%S")

    cursor.close()
    conn.close()

    return jsonify({"status": "success", "messages": messages})


@app.route("/api/messages", methods=["POST"])
def send_message_api():
    if not request.is_json:
        return (
            jsonify(
                {"status": "error", "message": "Content-Type must be application/json"}
            ),
            400,
        )

    data = request.json
    required_fields = ["content", "message_type"]
    if not all(field in data for field in required_fields):
        return jsonify({"status": "error", "message": "Missing required fields"}), 400

    sender = session.get("username")
    if not sender:
        return jsonify({"status": "error", "message": "Not authenticated"}), 401

    # Encrypt message
    encrypted_content = fernet.encrypt(data["content"].encode()).decode()

    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO messages (sender, content, message_type, recipient, timestamp)
        VALUES (%s, %s, %s, %s, %s)
    """,
        (
            sender,
            encrypted_content,
            data["message_type"],
            data.get("recipient"),
            datetime.now(),
        ),
    )

    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"status": "success", "message": "Message sent successfully"})


@socketio.on("connect")
def handle_connect():
    if "username" in session:
        username = session["username"]
        users[request.sid] = username
        join_room(username)
        emit("system_message", {"message": f"{username} has joined"}, broadcast=True)
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT m.*, u.public_key FROM messages m join users u on m.sender = u.username where (recipient = %s or sender = %s) and message_type = 'private'",
            (username, username),
        )
        messages = cursor.fetchall()
        cursor.close()
        conn.close()
        for message in messages:
            msg = {
                "sender": message[1],
                "content": message[2],
                "timestamp": message[5].strftime("%Y-%m-%d %H:%M:%S"),
                "type": message[3],
                "iv": message[6],
                "encrypted": True,
                "publicKey": message[8],
            }

            emit("message", msg, room=username)
        # emit('live_users', {'users': list(users.values())}, broadcast=True)


@socketio.on("message")
def handle_message(data):
    if "username" not in session:
        emit("system_message", {"message": "Not authenticated"}, broadcast=True)
        return

    sender = session["username"]
    content = data.get("content", "")
    message_type = data.get("type", "broadcast")
    recipient = data.get("recipient", None)

    # Encrypt message
    # encrypted_content = fernet.encrypt(content.encode()).decode()

    # Store in database
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO messages (sender, content, message_type, recipient, timestamp, iv)
        VALUES (%s, %s, %s, %s, %s, %s)
    """,
        (
            sender,
            content,
            message_type,
            recipient,
            datetime.now(),
            data.get("iv", None),
        ),
    )
    conn.commit()
    cursor.close()
    conn.close()

    # Prepare message for sending
    message = {
        "sender": sender,
        "content": content,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": message_type,
        "iv": data.get("iv", None),
        "encrypted": data.get("encrypted", False),
    }

    if message_type == "private" and recipient:
        emit("message", message, room=recipient)
        emit("message", message, room=sender)
    else:
        emit("message", message, broadcast=True)


@socketio.on("disconnect")
def handle_disconnect():
    if request.sid in users:
        username = users[request.sid]
        del users[request.sid]
        try:
            del user_public_keys[username]
        except:
            pass
        emit("system_message", {"message": f"{username} has left"}, broadcast=True)
        emit(
            "live_users",
            {
                "users": list(
                    users.values().map(
                        lambda x: {"name": x, "publicKey": user_public_keys[x]}
                    )
                )
            },
            broadcast=True,
        )


@socketio.on("public_key")
def handle_public_key(data):
    sender = session.get("username")
    public_key = data.get("publicKey")
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET public_key = %s WHERE username = %s", (public_key, sender))
    conn.commit()
    cursor.close()
    conn.close()

    if sender and public_key:
        # Store the public key for the sender
        if sender not in user_public_keys:
            user_public_keys[sender] = public_key
        # user_public_keys[sender][recipient] = public_key

        usersWithKeys = []
        for user in user_public_keys:
            if user_public_keys[user]:
                usersWithKeys.append(
                    {"name": user, "publicKey": user_public_keys[user]}
                )

        emit("live_users", {"users": usersWithKeys}, broadcast=True)
        # Notify the recipient about the public key
        # socketio.emit('public_key_received', {
        #     'sender': sender,
        #     'publicKey': public_key
        # }, room=recipient)

        logging.info(f"Public key received from {sender}")


@app.errorhandler(404)
def not_found_error(error):
    logging.error(f"404 error: {request.url}")
    return jsonify({"status": "error", "message": "Resource not found"}), 404


@app.errorhandler(500)
def internal_error(error):
    logging.error(f"500 error: {str(error)}")
    return jsonify({"status": "error", "message": "Internal server error"}), 500


@app.before_request
def log_request():
    logging.info(
        f"Request: {request.method} {request.url} - Client: {request.remote_addr}"
    )


@app.after_request
def log_response(response):
    logging.info(f"Response: {response.status} to {request.remote_addr}")
    return response


def start_packet_capture():
    start_capture()


if __name__ == "__main__":
    # Start packet capture in a separate thread
    capture_thread = threading.Thread(target=start_packet_capture)
    capture_thread.daemon = True
    capture_thread.start()

    logging.info("Starting secure messaging application")
    try:
        init_db()
        logging.info("Database initialized successfully")
        socketio.run(app, debug=True, host="0.0.0.0", port=5000)
    except Exception as e:
        logging.error(f"Failed to start application: {str(e)}")
