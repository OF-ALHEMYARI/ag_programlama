# Secure Web-Based Messaging Application

A simple yet secure web-based messaging application with end-to-end encryption.

## Features

- End-to-end encrypted messaging using Fernet encryption
- Real-time messaging with WebSocket
- Support for broadcast and private messages
- Message persistence with MySQL
- Simple web interface using Bootstrap
- No complex dependencies or build tools required

## Tech Stack

- **Backend**: Python Flask
- **Database**: MySQL
- **Frontend**: HTML, JavaScript, Bootstrap
- **Real-time Communication**: Flask-SocketIO
- **Encryption**: Fernet (symmetric encryption)

## Prerequisites

1. Python 3.8 or higher
2. MySQL Server
3. Web browser

## Setup Instructions

1. Create a MySQL database:
```sql
CREATE DATABASE secure_messaging;
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Configure the database:
Edit the db_config in app.py to match your MySQL settings:
```python
db_config = {
    'host': 'localhost',
    'user': 'your_username',
    'password': 'your_password',
    'database': 'secure_messaging'
}
```

4. Run the application:
```bash
python app.py
```

5. Access the application:
Open your web browser and navigate to `http://localhost:5000`

## Usage

1. Login with any username (authentication is simplified for demo)
2. Send messages:
   - **Broadcast**: Select "Broadcast" and type your message
   - **Private**: Select "Private", enter recipient's username, and type your message
3. Messages are automatically encrypted before being stored in the database
4. Real-time updates for all connected users

## Security Features

- End-to-end encryption using Fernet
- Secure WebSocket communication
- SQL injection prevention
- XSS protection

## Development

The application structure is simple:
- `app.py`: Main application file with Flask routes and WebSocket handlers
- `templates/`: HTML templates
  - `login.html`: Login page
  - `chat.html`: Main chat interface

## Production Deployment

For production:
1. Change the secret key in app.py
2. Enable HTTPS
3. Implement proper user authentication
4. Set up proper database backup
5. Use a production-grade server (e.g., Gunicorn)
