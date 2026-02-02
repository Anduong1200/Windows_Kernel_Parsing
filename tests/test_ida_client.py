"""
Unit tests for IDAClient.

Tests:
- Connection handling
- Command serialization
- Fragmented packet handling
- Progress callback
- Error handling
"""

import json
import struct
import socket
import threading
import time
import unittest
from unittest.mock import Mock, patch, MagicMock


class MockIDAServer:
    """
    Mock IDA server for testing IDAClient.
    
    Simulates the socket protocol used by ida_analysis_script.py.
    """
    
    def __init__(self, port: int = 0):
        self.server_socket = None
        self.client_socket = None
        self.port = port
        self.running = False
        self._responses = []
        self._received_commands = []
    
    def start(self):
        """Start the mock server."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('127.0.0.1', self.port))
        self.server_socket.listen(1)
        self.port = self.server_socket.getsockname()[1]
        self.running = True
    
    def accept_client(self):
        """Accept client connection and send handshake."""
        self.client_socket, _ = self.server_socket.accept()
        
        # Send READY handshake
        handshake = {
            "status": "READY",
            "version": "2.0-test",
            "pid": 12345
        }
        self._send_msg(handshake)
    
    def _send_msg(self, data: dict):
        """Send length-prefixed JSON message."""
        json_data = json.dumps(data).encode('utf-8')
        msg = struct.pack('>I', len(json_data)) + json_data
        self.client_socket.sendall(msg)
    
    def _recv_msg(self) -> dict:
        """Receive length-prefixed JSON message."""
        raw_len = self._recv_exactly(4)
        if not raw_len:
            return None
        msg_len = struct.unpack('>I', raw_len)[0]
        data = self._recv_exactly(msg_len)
        return json.loads(data.decode('utf-8'))
    
    def _recv_exactly(self, n: int) -> bytes:
        """Receive exactly n bytes."""
        data = b''
        while len(data) < n:
            chunk = self.client_socket.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    
    def queue_response(self, response: dict):
        """Queue a response to send when command is received."""
        self._responses.append(response)
    
    def handle_one_command(self) -> dict:
        """Receive one command and send queued response."""
        cmd = self._recv_msg()
        if cmd:
            self._received_commands.append(cmd)
            
            if self._responses:
                response = self._responses.pop(0)
                self._send_msg(response)
        
        return cmd
    
    def send_progress(self, percent: int, message: str):
        """Send a progress message."""
        self._send_msg({
            "type": "progress",
            "percent": percent,
            "message": message
        })
    
    def get_received_commands(self) -> list:
        """Get list of received commands."""
        return self._received_commands
    
    def close(self):
        """Close the server."""
        self.running = False
        if self.client_socket:
            self.client_socket.close()
        if self.server_socket:
            self.server_socket.close()


class TestIDAClientConnection(unittest.TestCase):
    """Test IDAClient connection handling."""
    
    def setUp(self):
        """Set up mock server."""
        self.server = MockIDAServer()
        self.server.start()
    
    def tearDown(self):
        """Clean up server."""
        self.server.close()
    
    def test_connect_receives_handshake(self):
        """Test that client correctly receives READY handshake."""
        # Import here to avoid import errors if module not available
        import sys
        sys.path.insert(0, 'd:/examinate/18/project')
        
        from logic_flow.core.analyzer import IDAClient
        
        # Start server in background
        def server_thread():
            self.server.accept_client()
        
        thread = threading.Thread(target=server_thread)
        thread.start()
        
        # Create client with mock process
        with patch.object(IDAClient, 'start_server'):
            client = IDAClient.__new__(IDAClient)
            client.ida_path = "test"
            client.driver_path = "test.sys"
            client.socket_timeout = 5.0
            client.host = '127.0.0.1'
            client.sock = None
            client.proc = None
            
            # Connect directly to mock server
            client._connect(self.server.port)
            
            # Verify handshake was received
            self.assertEqual(client._server_version, "2.0-test")
            self.assertEqual(client._server_pid, 12345)
        
        thread.join(timeout=2)


class TestIDAClientCommands(unittest.TestCase):
    """Test IDAClient command sending."""
    
    def setUp(self):
        """Set up mock server and client."""
        self.server = MockIDAServer()
        self.server.start()
        
        # Start server accept in background
        def server_thread():
            self.server.accept_client()
            # Handle commands in loop
            while self.server.running:
                try:
                    self.server.handle_one_command()
                except:
                    break
        
        self.server_thread = threading.Thread(target=server_thread)
        self.server_thread.start()
        time.sleep(0.1)  # Give server time to start
    
    def tearDown(self):
        """Clean up."""
        self.server.close()
        self.server_thread.join(timeout=2)
    
    def test_send_command_receives_response(self):
        """Test sending command and receiving response."""
        import sys
        sys.path.insert(0, 'd:/examinate/18/project')
        from logic_flow.core.analyzer import IDAClient
        
        # Queue response
        self.server.queue_response({
            "status": "success",
            "result": {"message": "pong"}
        })
        
        with patch.object(IDAClient, 'start_server'):
            client = IDAClient.__new__(IDAClient)
            client.ida_path = "test"
            client.driver_path = "test.sys"
            client.socket_timeout = 5.0
            client.host = '127.0.0.1'
            client.sock = None
            client.proc = None
            
            client._connect(self.server.port)
            
            response = client.send_command('ping')
            
            self.assertEqual(response['status'], 'success')
            self.assertEqual(response['result']['message'], 'pong')
    
    def test_progress_callback_invoked(self):
        """Test that progress callback is called for progress messages."""
        import sys
        sys.path.insert(0, 'd:/examinate/18/project')
        from logic_flow.core.analyzer import IDAClient
        
        progress_calls = []
        
        def progress_cb(percent, message):
            progress_calls.append((percent, message))
        
        # Server will send progress then response
        def custom_handler():
            self.server.accept_client()
            cmd = self.server._recv_msg()
            if cmd:
                # Send progress first
                self.server.send_progress(50, "Processing...")
                # Then send final response
                self.server._send_msg({
                    "status": "success",
                    "result": {}
                })
        
        # Restart with custom handler
        self.server.close()
        self.server = MockIDAServer()
        self.server.start()
        
        thread = threading.Thread(target=custom_handler)
        thread.start()
        
        with patch.object(IDAClient, 'start_server'):
            client = IDAClient.__new__(IDAClient)
            client.ida_path = "test"
            client.driver_path = "test.sys"
            client.socket_timeout = 5.0
            client.host = '127.0.0.1'
            client.sock = None
            client.proc = None
            
            client._connect(self.server.port)
            
            response = client.send_command('analyze', {}, progress_callback=progress_cb)
        
        thread.join(timeout=2)
        
        # Verify progress was received
        self.assertEqual(len(progress_calls), 1)
        self.assertEqual(progress_calls[0], (50, "Processing..."))


class TestFragmentedPackets(unittest.TestCase):
    """Test handling of fragmented TCP packets."""
    
    def test_recv_exactly_handles_fragmentation(self):
        """Test that recv_exactly properly handles fragmented data."""
        import sys
        sys.path.insert(0, 'd:/examinate/18/project')
        from logic_flow.core.analyzer import IDAClient
        
        # Create connected socket pair
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(('127.0.0.1', 0))
        server_sock.listen(1)
        port = server_sock.getsockname()[1]
        
        # Connect client
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect(('127.0.0.1', port))
        
        conn, _ = server_sock.accept()
        
        # Create client with our socket
        with patch.object(IDAClient, 'start_server'):
            client = IDAClient.__new__(IDAClient)
            client.ida_path = "test"
            client.driver_path = "test.sys"
            client.socket_timeout = 5.0
            client.sock = client_sock
            
            # Send data in fragments
            test_data = b'Hello, this is fragmented data!'
            
            def send_fragmented():
                time.sleep(0.05)
                conn.send(test_data[:10])
                time.sleep(0.05)
                conn.send(test_data[10:20])
                time.sleep(0.05)
                conn.send(test_data[20:])
            
            thread = threading.Thread(target=send_fragmented)
            thread.start()
            
            # Receive all data
            received = client._recv_exactly(len(test_data))
            
            thread.join()
            
            self.assertEqual(received, test_data)
        
        client_sock.close()
        conn.close()
        server_sock.close()


if __name__ == '__main__':
    unittest.main()
