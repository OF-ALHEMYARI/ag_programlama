import mysql.connector
from datetime import datetime
from cryptography.fernet import Fernet

# Database configuration
db_config = {
    'host': '127.0.0.1',
    'port': 3306,
    'user': 'root',
    'password': 'root',
    'database': 'secure_messaging'
}

def view_messages():
    try:
        # Connect to database
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        
        print("\n=== Messages in Database ===")
        print("-" * 50)
        
        # Get messages
        cursor.execute("""
            SELECT id, sender, content, message_type, recipient, timestamp 
            FROM messages 
            ORDER BY timestamp DESC
        """)
        
        messages = cursor.fetchall()
        
        if not messages:
            print("No messages found in the database.")
        else:
            for msg in messages:
                id, sender, content, msg_type, recipient, timestamp = msg
                
                # Format the message type and recipient
                if msg_type == 'private':
                    msg_info = f"Private message to {recipient}"
                else:
                    msg_info = "Broadcast message"
                
                # Format the timestamp
                formatted_time = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                
                print(f"\nMessage ID: {id}")
                print(f"Time: {formatted_time}")
                print(f"From: {sender}")
                print(f"Type: {msg_info}")
                print(f"Encrypted Content: {content}")
                print("-" * 50)
        
        # Get user count
        cursor.execute("SELECT COUNT(DISTINCT sender) FROM messages")
        user_count = cursor.fetchone()[0]
        
        # Get message count by type
        cursor.execute("""
            SELECT message_type, COUNT(*) 
            FROM messages 
            GROUP BY message_type
        """)
        type_counts = cursor.fetchall()
        
        print("\n=== Statistics ===")
        print(f"Total unique users: {user_count}")
        print("Message counts by type:")
        for msg_type, count in type_counts:
            print(f"- {msg_type}: {count}")
        
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    view_messages()
