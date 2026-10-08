import socket
import threading
import time

class MiniHoneypot:
    def __init__(self, host='0.0.0.0', port=2222, callback_on_hit=None):
        """
        port=2222 is used as a decoy SSH port (or port 80/22 with admin privileges).
        callback_on_hit: Function in risk_engine/alert_manager to trigger when hit.
        """
        self.host = host
        self.port = port
        self.callback = callback_on_hit
        self.is_running = False
        self.trapped_ips = set()

    def start_trap(self):
        self.is_running = True
        thread = threading.Thread(target=self._listen, daemon=True)
        thread.start()
        print(f"[+] Honeypot Trap Active on Port {self.port}...")

    def _listen(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server.bind((self.host, self.port))
            server.listen(5)
            server.settimeout(1.0) # Prevent socket blocking on shutdown
            
            while self.is_running:
                try:
                    client_socket, client_address = server.accept()
                    attacker_ip = client_address[0]
                    self.trapped_ips.add(attacker_ip)
                    
                    print(f"[ALERT] HONEYPOT TRAP TRIGGERED BY: {attacker_ip}")
                    
                    # Send alert to Risk Engine / Alert Manager
                    if self.callback:
                        self.callback(attacker_ip, self.port)
                        
                    # Send fake response banner to keep attacker engaged briefly
                    client_socket.send(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
                    time.sleep(0.5)
                    client_socket.close()
                except socket.timeout:
                    continue
        except Exception as e:
            print(f"[-] Honeypot Error: {e}")
        finally:
            server.close()

    def stop_trap(self):
        self.is_running = False