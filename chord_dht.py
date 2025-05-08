import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
import socket
import threading
import pickle
import time

class User:
    def _init_(self, username):
        self.username = username
        # Generate RSA key pair for the user
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()

    def encrypt(self, message, recipient_public_key):
        return recipient_public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt(self, ciphertext):
        return self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()

    def sign_message(self, message):
        signature = self.private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

class Node:
    def _init_(self, node_id, max_id, port):
        self.node_id = node_id
        self.keys = {}  # key: (encrypted_value, owner_username)
        self.successor = self  # Point to itself initially
        self.predecessor = None
        self.max_id = max_id
        self.authorized_users = {}  # username: public_key
        self.port = port
        self.address = ('localhost', port)
        self.running = True

        # Start server thread
        threading.Thread(target=self.run_server, daemon=True).start()

    def run_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(self.address)
            server.listen()
            print(f"Node {self.node_id} listening on {self.port}")

            while self.running:
                conn, addr = server.accept()
                threading.Thread(target=self.handle_connection, args=(conn, addr), daemon=True).start()

    def handle_connection(self, conn, addr):
        with conn:
            data = conn.recv(1024)
            if data:
                request = pickle.loads(data)
                response = self.handle_request(request)
                conn.sendall(pickle.dumps(response))

    def handle_request(self, request):
        if request['type'] == 'find_successor':
            return self.find_successor(request['key']).node_id
        elif request['type'] == 'store':
            self.store_key(request['key'], request['encrypted_value'], request['owner_username'])
            return True
        elif request['type'] == 'lookup':
            return self.keys.get(request['key'], (None, None))
        elif request['type'] == 'verify_user':
            return self.verify_user(request['username'], request['signature'], request['message'])
        elif request['type'] == 'update_predecessor':
            self.predecessor = next(node for node in chord.nodes if node.node_id == request['node_id'])
            return True
        elif request['type'] == 'update_successor':
            self.successor = next(node for node in chord.nodes if node.node_id == request['node_id'])
            return True
        elif request['type'] == 'get_predecessor':
            return self.predecessor.node_id if self.predecessor else None
        return None

    def send_request(self, address, request):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(address)
            s.sendall(pickle.dumps(request))
            data = s.recv(1024)
        return pickle.loads(data)

    def add_authorized_user(self, user):
        self.authorized_users[user.username] = user.public_key

    def verify_user(self, username, signature, message):
        public_key = self.authorized_users.get(username)
        if not public_key:
            return False
        try:
            public_key.verify(
                signature,
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    def store_key(self, key, encrypted_value, owner_username):
        self.keys[key] = (encrypted_value, owner_username)

    def find_successor(self, key):
        if self.predecessor is None or self.successor is None:
            return self
        if self.predecessor.node_id < self.node_id:
            # Normal case
            if self.predecessor.node_id < key <= self.node_id:
                return self
        else:
            # Wrap-around case
            if key > self.predecessor.node_id or key <= self.node_id:
                return self
        request = {'type': 'find_successor', 'key': key}
        successor_id = self.send_request(self.successor.address, request)
        return next(node for node in chord.nodes if node.node_id == successor_id)

    def stop(self):
        self.running = False

    def join(self, existing_node_address):
        request = {'type': 'find_successor', 'key': self.node_id}
        successor_id = self.send_request(existing_node_address, request)
        self.successor = next(node for node in chord.nodes if node.node_id == successor_id)
        self.predecessor = None
        request = {'type': 'update_predecessor', 'node_id': self.node_id}
        self.send_request(self.successor.address, request)
        if self.successor != self:
            pred_id = self.send_request(self.successor.address, {'type': 'get_predecessor'})
            if pred_id is not None:
                self.predecessor = next(node for node in chord.nodes if node.node_id == pred_id)
                request = {'type': 'update_successor', 'node_id': self.node_id}
                self.send_request(self.predecessor.address, request)

class ChordDHT:
    def _init_(self, m=4):
        self.nodes = []
        self.max_id = 2 ** m

    def add_node(self, node, existing_node_address=None):
        self.nodes.append(node)
        if existing_node_address:
            node.join(existing_node_address)
        self.update_ring()

    def update_ring(self):
        sorted_nodes = sorted(self.nodes, key=lambda node: node.node_id)
        for i, node in enumerate(sorted_nodes):
            node.successor = sorted_nodes[(i + 1) % len(sorted_nodes)]
            node.predecessor = sorted_nodes[(i - 1) % len(sorted_nodes)]
        self.nodes = sorted_nodes  # Keep nodes sorted

    def hash_key(self, key):
        key_hash = int(hashlib.sha1(key.encode()).hexdigest(), 16)
        return key_hash % self.max_id

    def store(self, key, value, owner_user, signature):
        key_hash = self.hash_key(key)
        node = self.nodes[0].find_successor(key_hash)
        # Verify the owner's signature
        request = {
            'type': 'verify_user',
            'username': owner_user.username,
            'signature': signature,
            'message': f"store:{key}:{value}"
        }
        if not node.send_request(node.address, request):
            print(f"Authentication failed for user {owner_user.username}. Cannot store key.")
            return
        # Encrypt the value with the owner's public key
        encrypted_value = owner_user.encrypt(value, owner_user.public_key)
        store_request = {
            'type': 'store',
            'key': key,
            'encrypted_value': encrypted_value,
            'owner_username': owner_user.username
        }
        node.send_request(node.address, store_request)
        print(f"Key '{key}' stored by {owner_user.username} on node {node.node_id}.")

    def lookup(self, key, requesting_user, signature, user_private_key=None):
        key_hash = self.hash_key(key)
        node = self.nodes[0].find_successor(key_hash)
        lookup_request = {'type': 'lookup', 'key': key}
        encrypted_value, owner_username = node.send_request(node.address, lookup_request)
        if encrypted_value is None:
            print(f"Key '{key}' not found in the DHT.")
            return None
        # Verify the requesting user's signature
        request = {
            'type': 'verify_user',
            'username': requesting_user.username,
            'signature': signature,
            'message': f"lookup:{key}"
        }
        if not node.send_request(node.address, request):
            print(f"Authentication failed for user {requesting_user.username}. Cannot lookup key.")
            return None
        # Retrieve the owner user to decrypt the value
        owner_user = next((user for user in authorized_users if user.username == owner_username), None)
        if owner_user is None:
            print(f"Owner '{owner_username}' not found.")
            return None
        decrypted_value = owner_user.decrypt(encrypted_value)
        print(f"Key '{key}' retrieved by {requesting_user.username}: {decrypted_value} (owned by {owner_username}).")
        return decrypted_value

if _name_ == '_main_':
    chord = ChordDHT(m=4)  # Identifier space: 0-15

    # Create users
    user1 = User("Alice")
    user2 = User("Bob")
    attacker = User("Eve")  # Unauthorized user

    authorized_users = [user1, user2]  # List of authorized users

    # Assign node IDs within the identifier space and create nodes with different ports
    node_ports = [5000, 5001, 5002, 5003, 5004]
    node_ids = [1, 4, 7, 10, 13]
    nodes = [Node(node_id, chord.max_id, port) for node_id, port in zip(node_ids, node_ports)]

    # Add the first node to the ring without existing node address
    chord.add_node(nodes[0])

    # Add remaining nodes to the ring
    for node in nodes[1:]:
        chord.add_node(node, nodes[0].address)

    # Add authorized users to all nodes
    for node in chord.nodes:
        for user in authorized_users:
            node.add_authorized_user(user)

    time.sleep(2)  # Give nodes time to start up

    # User1 (Alice) stores a key-value pair
    message_store = f"store:hello:world"
    signature_store = user1.sign_message(message_store)
    chord.store('hello', 'world', user1, signature_store)

    # User2 (Bob) stores another key-value pair
    message_store_bob = f"store:foo:bar"
    signature_store_bob = user2.sign_message(message_store_bob)
    chord.store('foo', 'bar', user2, signature_store_bob)

    time.sleep(2)  # Allow time for storing operations

    # Authorized user1 (Alice) retrieves her key
    message_lookup = f"lookup:hello"
    signature_lookup = user1.sign_message(message_lookup)
    chord.lookup('hello', user1, signature_lookup)

    # Authorized user2 (Bob) retrieves his key
    message_lookup_bob = f"lookup:foo"
    signature_lookup_bob = user2.sign_message(message_lookup_bob)
    chord.lookup('foo', user2, signature_lookup_bob)

    # Unauthorized user (Eve) attempts to retrieve Alice's key
    message_lookup_eve = f"lookup:hello"
    signature_lookup_eve = attacker.sign_message(message_lookup_eve)
    chord.lookup('hello', attacker, signature_lookup_eve)  # Should fail

    # Unauthorized user (Eve) attempts to store a key
    message_store_eve = f"store:secret:12345"
    signature_store_eve = attacker.sign_message(message_store_eve)
    chord.store('secret', '12345', attacker, signature_store_eve)  # Should fail

    # Stop all nodes' servers
    for node in chord.nodes:
        node.stop()