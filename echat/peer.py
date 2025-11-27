import socket
import threading
import base64
import sys

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


class PeerChat:
    
    def __init__(self, port=9999):
        self.port = port
        self.peer_socket = None
        self.cipher = None
        self.exit_flag = threading.Event()
        self.connected = False
        self.incoming_connection = None
        self.connection_accepted = threading.Event()
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    def start_listener(self):
        try:
            self.listen_socket.bind(('0.0.0.0', self.port))
            self.listen_socket.listen(1)
            self.listen_socket.settimeout(1)
        except OSError as e:
            print(f"Error: Could not bind to port {self.port}. {e}")
            sys.exit(1)
    
    def listen_for_connections(self):
        while not self.exit_flag.is_set() and not self.connected:
            try:
                conn, addr = self.listen_socket.accept()
                if self.connected:
                    conn.close()
                    continue
                    
                print(f"\n\n{'='*50}")
                print(f"  Incoming connection from {addr[0]}")
                print(f"{'='*50}")
                
                response = input("Accept connection? (y/n): ").strip().lower()
                
                if response == 'y':
                    conn.send(b'ACCEPTED')
                    self.peer_socket = conn
                    self.incoming_connection = addr
                    self.connection_accepted.set()
                    return
                else:
                    conn.send(b'REJECTED')
                    conn.close()
                    print("Connection rejected. Waiting for connections...")
                    
            except socket.timeout:
                continue
            except Exception:
                if not self.exit_flag.is_set():
                    continue
                break
    
    def connect_to_peer(self, peer_ip):
        print(f"\nConnecting to {peer_ip}:{self.port}...")
        
        try:
            self.peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.peer_socket.settimeout(10)
            self.peer_socket.connect((peer_ip, self.port))
            
            print("Waiting for peer to accept...")
            response = self.peer_socket.recv(1024)
            
            if response == b'ACCEPTED':
                print("Connection accepted!")
                self.peer_socket.settimeout(None)
                return True
            else:
                print("Connection rejected by peer.")
                self.peer_socket.close()
                self.peer_socket = None
                return False
                
        except socket.timeout:
            print("Connection timed out. Peer may not be available.")
            return False
        except ConnectionRefusedError:
            print(f"Could not connect. Make sure peer is running echat on {peer_ip}")
            return False
        except Exception as e:
            print(f"Connection failed: {e}")
            return False
    
    def perform_key_exchange(self, is_initiator):
        print("\nEstablishing secure connection...")
        
        if is_initiator:
            parameters = dh.generate_parameters(generator=2, key_size=2048)
            private_key = parameters.generate_private_key()
            public_key = private_key.public_key()
            
            params_bytes = parameters.parameter_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.ParameterFormat.PKCS3
            )
            self.peer_socket.send(len(params_bytes).to_bytes(4, 'big'))
            self.peer_socket.send(params_bytes)
            
            pubkey_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.peer_socket.send(len(pubkey_bytes).to_bytes(4, 'big'))
            self.peer_socket.send(pubkey_bytes)
            
            peer_pubkey_length = int.from_bytes(self.peer_socket.recv(4), 'big')
            peer_pubkey_bytes = self.peer_socket.recv(peer_pubkey_length)
            peer_public_key = serialization.load_pem_public_key(peer_pubkey_bytes)
            
        else:
            params_length = int.from_bytes(self.peer_socket.recv(4), 'big')
            params_bytes = self.peer_socket.recv(params_length)
            parameters = serialization.load_pem_parameters(params_bytes)
            
            peer_pubkey_length = int.from_bytes(self.peer_socket.recv(4), 'big')
            peer_pubkey_bytes = self.peer_socket.recv(peer_pubkey_length)
            peer_public_key = serialization.load_pem_public_key(peer_pubkey_bytes)
            
            private_key = parameters.generate_private_key()
            public_key = private_key.public_key()
            
            pubkey_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.peer_socket.send(len(pubkey_bytes).to_bytes(4, 'big'))
            self.peer_socket.send(pubkey_bytes)
        
        shared_secret = private_key.exchange(peer_public_key)
        
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'tchat handshake'
        ).derive(shared_secret)
        
        fernet_key = base64.urlsafe_b64encode(derived_key)
        self.cipher = Fernet(fernet_key)
        
        print("Secure connection established!")
        print("=" * 50)
        print("  You can now chat securely. Type 'exit' to quit.")
        print("=" * 50)
        print()
    
    def receive_messages(self):
        while not self.exit_flag.is_set():
            try:
                data = self.peer_socket.recv(4096)
                if not data:
                    print("\nPeer disconnected.")
                    self.exit_flag.set()
                    break
                    
                decrypted = self.cipher.decrypt(data)
                message = decrypted.decode('utf-8')
                
                if message == 'exit':
                    print("\nPeer has left the chat.")
                    self.exit_flag.set()
                    break
                    
                print(f"Peer: {message}")
                
            except Exception:
                if not self.exit_flag.is_set():
                    print("\nConnection lost.")
                    self.exit_flag.set()
                break
    
    def send_messages(self):
        try:
            while not self.exit_flag.is_set():
                message = input()
                
                if self.exit_flag.is_set():
                    break
                    
                encrypted = self.cipher.encrypt(message.encode('utf-8'))
                self.peer_socket.send(encrypted)
                
                if message == 'exit':
                    self.exit_flag.set()
                    break
                    
        except (KeyboardInterrupt, EOFError):
            self.exit_flag.set()
    
    def chat(self, is_initiator):
        self.perform_key_exchange(is_initiator)
        self.connected = True
        
        recv_thread = threading.Thread(target=self.receive_messages, daemon=True)
        recv_thread.start()
        
        self.send_messages()
        
        recv_thread.join(timeout=2)
    
    def cleanup(self):
        self.exit_flag.set()
        if self.peer_socket:
            try:
                self.peer_socket.close()
            except:
                pass
        try:
            self.listen_socket.close()
        except:
            pass
    
    def run(self):
        local_ip = self.get_local_ip()
        
        print("=" * 50)
        print("  echat - Encrypted P2P Terminal Chat")
        print("=" * 50)
        print(f"\n  Your IP: {local_ip}")
        print(f"  Listening on port: {self.port}")
        print("\n  Share your IP with others to let them connect.")
        print("=" * 50)
        
        self.start_listener()
        
        listener_thread = threading.Thread(target=self.listen_for_connections, daemon=True)
        listener_thread.start()
        
        print("\nOptions:")
        print("  1. Connect to a peer (enter their IP)")
        print("  2. Wait for incoming connections")
        print("  3. Exit")
        
        try:
            while not self.exit_flag.is_set() and not self.connected:
                choice = input("\nEnter peer IP to connect, or press Enter to wait: ").strip()
                
                if self.connection_accepted.is_set():
                    print(f"\nConnected with {self.incoming_connection[0]}")
                    self.chat(is_initiator=False)
                    break
                
                if choice.lower() == 'exit' or choice == '3':
                    print("Goodbye!")
                    break
                elif choice == '' or choice == '2':
                    print("Waiting for incoming connections... (Press Ctrl+C to cancel)")
                    try:
                        while not self.exit_flag.is_set() and not self.connection_accepted.is_set():
                            self.connection_accepted.wait(timeout=1)
                        
                        if self.connection_accepted.is_set():
                            print(f"\nConnected with {self.incoming_connection[0]}")
                            self.chat(is_initiator=False)
                            break
                    except KeyboardInterrupt:
                        print("\nCancelled. Back to menu.")
                        continue
                elif choice == '1':
                    peer_ip = input("Enter peer IP: ").strip()
                    if peer_ip and self.connect_to_peer(peer_ip):
                        self.chat(is_initiator=True)
                        break
                else:
                    if self.connect_to_peer(choice):
                        self.chat(is_initiator=True)
                        break
                        
        except KeyboardInterrupt:
            print("\n\nGoodbye!")
        finally:
            self.cleanup()


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Encrypted P2P Terminal Chat')
    parser.add_argument('-p', '--port', type=int, default=9999,
                        help='Port to use (default: 9999)')
    args = parser.parse_args()
    
    chat = PeerChat(port=args.port)
    chat.run()


if __name__ == "__main__":
    main()
