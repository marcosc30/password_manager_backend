from flask import Flask, request, jsonify
from azure.cosmos import exceptions, CosmosClient, PartitionKey
import hashlib
import base64
import os

# user_id database:
    # user_id INTEGER PRIMARY KEY,
    # account BLOB NOT NULL,
    # hashed_master_password BLOB NOT NULL,
    # salt BLOB,
    # kdf_salt BLOB,
    # open_instances INTEGER NOT NULL

# passwords database:
    # entry_id INTEGER PRIMARY KEY,
    # user_id INTEGER NOT NULL,
    # account BLOB NOT NULL,
    # password BLOB NOT NULL,
    # website BLOB NOT NULL

app = Flask(__name__)

# Initialize the Cosmos client
endpoint = os.getenv("COSMOS_DB_ENDPOINT")
key = os.getenv("COSMOS_DB_KEY")
client = CosmosClient(endpoint, key)

# Initialize databases and containers
database_name = 'pm-cloud-db'

# User Accounts Table
users_container_name = 'user_id'
users_container = client.get_database_client(database_name).get_container_client(users_container_name)

# Passwords Table
passwords_container_name = 'passwords'
passwords_container = client.get_database_client(database_name).get_container_client(passwords_container_name)

@app.route('/get_user_id', methods=['GET'])
def get_user_id():
    account_name = request.json.get('account_name')
    
    if not account_name:
        return jsonify({"error": "Account name is required"}), 400
    
    # Retrieve user_id, salt, and kdf_salt from the Users Table
    query = "SELECT * FROM c WHERE c.account=@account_name"
    parameters = [{"name": "@account_name", "value": account_name}]

    try:
        user_items = list(users_container.query_items(
            query=query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))

        if not user_items:
            # We get the admin account and send that
            query = "SELECT * FROM c WHERE c.account=@account_name"
            parameters = [{"name": "@account_name", "value": "admin"}]
            user_items = list(users_container.query_items(
                query=query,
                parameters=parameters,
                enable_cross_partition_query=True
            ))

            if not user_items:
                return jsonify({"error": "Account not found"}), 404

        user_item = user_items[0]  # Assuming account_name is unique
        user_id = user_item['user_id']
        salt = user_item['salt']
        kdf_salt = user_item['kdf_salt']

        return jsonify({"user_id": user_id, "salt": salt, "kdf_salt": kdf_salt}), 200

    except exceptions.CosmosHttpResponseError as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/register_user', methods=['POST'])
def register_user():
    account_name = request.json.get('account_name')
    hashed_master_password = request.json.get('hashed_master_password')
    salt = request.json.get('salt')
    kdf_salt = request.json.get('kdf_salt')
    
    if not account_name or not hashed_master_password or not salt or not kdf_salt:
        return jsonify({"error": "Account name, hashed password, salt, and kdf_salt are required"}), 400

    # Check if the account name already exists
    query = "SELECT * FROM c WHERE c.account=@account_name"
    parameters = [{"name": "@account_name", "value": account_name}]

    try:
        user_items = list(users_container.query_items(
            query=query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))

        if user_items:
            return jsonify({"error": "Account name already exists"}), 409

        # Insert the new user into the Users Table
        user_item = {
            "account": account_name,
            "hashed_master_password": hashed_master_password,
            "salt": salt,
            "kdf_salt": kdf_salt,
            "open_instances": 0
        }

        users_container.create_item(body=user_item)

        return jsonify({"message": "User registered successfully"}), 201

    except exceptions.CosmosHttpResponseError as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_accounts', methods=['POST'])
def get_accounts():
    # Receives an account name and a hashed password from the client
    account_name = request.json.get('account_name')
    hashed_password = request.json.get('hashed_password')
    
    if not account_name or not hashed_password:
        return jsonify({"error": "Account name and password are required"}), 400

    # Step 1: Retrieve user details from the Users Table
    query = "SELECT * FROM c WHERE c.account=@account_name"
    parameters = [{"name": "@account_name", "value": account_name}]
    
    try:
        user_items = list(users_container.query_items(
            query=query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))
        
        if not user_items:
            return jsonify({"error": "Account not found"}), 404
        
        # Step 2: Check if the password is correct
        user_item = user_items[0]  # Assuming account_name is unique
        stored_password_hash = user_item['hashed_master_password']
        user_id = user_item['user_id']

        # Hash the provided password with the retrieved salt
        
        if hashed_password != stored_password_hash:
            return jsonify({"error": "Invalid password"}), 403

        # Step 3: Retrieve encrypted passwords from the Passwords Table
        query = "SELECT * FROM c WHERE c.user_id=@user_id"
        parameters = [{"name": "@user_id", "value": user_id}]
        
        passwords_items = list(passwords_container.query_items(
            query=query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))

        # Step 4: Increment the open_instances count
        user_item['open_instances'] += 1
        users_container.upsert_item(user_item)

        return jsonify(passwords_items), 200

    except exceptions.CosmosHttpResponseError as e:
        return jsonify({"error": str(e)}), 500

@app.route('/sync', methods=['POST'])
def sync():
    # Receives the data and user_id from the client
    data = request.json.get('data')
    user_id = request.json.get('user_id')

    if not user_id or not data:
        return jsonify({"error": "User ID and data are required"}), 400

    # Validate if there is only one open instance for this user_id
    query = "SELECT * FROM c WHERE c.user_id=@user_id"
    parameters = [{"name": "@user_id", "value": user_id}]

    try:
        user_items = list(users_container.query_items(
            query=query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))

        if not user_items:
            return jsonify({"error": "User ID not found"}), 404

        user_item = user_items[0]  # Assuming user_id is unique
        if user_item['open_instances'] == 0:
            return jsonify({"error": "No open instances detected"}), 403

        if user_item['open_instances'] != 1:
            return jsonify({"error": "Multiple open instances detected"}), 403
        
    except exceptions.CosmosHttpResponseError as e:
        return jsonify({"error": str(e)}), 500


    # Perform data synchronization logic

    try:
        for item in data:
            passwords_container.upsert_item(item)
        return jsonify({"message": "Sync successful"}), 200
    except exceptions.CosmosHttpResponseError as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
