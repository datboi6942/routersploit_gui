#!/usr/bin/env python3
"""
Simple console test server to verify console functionality.
This is a minimal implementation just to test the frontend-backend console connection.
"""

from flask import Flask, render_template, send_from_directory
from flask_socketio import SocketIO, emit
import os
import sys

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = 'console-test-secret'

socketio = SocketIO(app, cors_allowed_origins="*")

# Simple console state
console_clients = {}
command_history = []

@app.route('/')
def index():
    """Main test page."""
    return send_from_directory('.', 'console_test.html')

@app.route('/console-test')
def console_test():
    """Console test page."""
    return send_from_directory('.', 'console_test.html')

@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    print(f"✅ Client connected: {request.sid}")
    emit('status', {'running': False, 'current_module': None})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    session_id = request.sid
    if session_id in console_clients:
        del console_clients[session_id]
    print(f"❌ Client disconnected: {session_id}")

@socketio.on('console_connect')
def handle_console_connect():
    """Handle console connection."""
    from flask import request
    session_id = request.sid
    console_clients[session_id] = True
    print(f"🎉 Console client connected: {session_id}")
    
    emit('console_connected', {
        'prompt': 'test-rsf > ',
        'welcome': 'RouterSploit Console Test - Console connection successful!\nType "help" for test commands.'
    })

@socketio.on('console_disconnect')
def handle_console_disconnect():
    """Handle console disconnection."""
    from flask import request
    session_id = request.sid
    if session_id in console_clients:
        del console_clients[session_id]
    print(f"🚪 Console client disconnected: {session_id}")

@socketio.on('console_command')
def handle_console_command(data):
    """Handle console command execution."""
    from flask import request
    try:
        command = data.get('command', '').strip()
        if not command:
            return
            
        print(f"📟 Console command from {request.sid}: {command}")
        command_history.append(command)
        
        # Simple command responses
        if command == 'help':
            response = """Test Console Commands:
====================

help          - Show this help
status        - Show console status  
echo <text>   - Echo back the text
history       - Show command history
clear         - Clear console
exit          - Exit console
test          - Run connection test
error         - Simulate an error

This is a test console to verify the frontend-backend connection works."""
        
        elif command == 'status':
            response = f"""Console Status:
- Connected clients: {len(console_clients)}
- Commands executed: {len(command_history)}
- Session ID: {request.sid}
- Console working: ✅ YES"""

        elif command.startswith('echo '):
            text = command[5:]
            response = f"Echo: {text}"
        
        elif command == 'history':
            if command_history:
                response = "Command History:\n" + "\n".join(f"{i+1}. {cmd}" for i, cmd in enumerate(command_history[-10:]))
            else:
                response = "No commands in history"
        
        elif command == 'clear':
            emit('console_clear')
            return
        
        elif command == 'exit':
            emit('console_exit')
            return
        
        elif command == 'test':
            response = """🧪 Connection Test Results:
✅ Frontend-Backend communication: WORKING
✅ Socket.IO connection: ACTIVE  
✅ Console handlers: FUNCTIONAL
✅ Command processing: SUCCESS
✅ Real-time updates: ENABLED

Your console is fully functional! 🎉"""
        
        elif command == 'error':
            emit('console_output', {
                'data': 'Simulated error: This is a test error message',
                'level': 'error'
            })
            emit('console_prompt', {'prompt': 'test-rsf > '})
            return
            
        else:
            response = f"Unknown command: '{command}'. Type 'help' for available commands."
        
        # Send response
        emit('console_output', {
            'data': response,
            'level': 'info'
        })
        
        # Send updated prompt
        emit('console_prompt', {
            'prompt': 'test-rsf > '
        })
        
    except Exception as e:
        print(f"❌ Console command error: {e}")
        emit('console_output', {
            'data': f"Error processing command: {str(e)}",
            'level': 'error'
        })

if __name__ == '__main__':
    print("🚀 Starting Simple Console Test Server...")
    print("📍 Access the test at: http://localhost:5000/")
    print("🔧 This server tests console frontend-backend communication")
    print("=" * 60)
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)