import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

password = "mysecretpassword22@"
hashed_password = hash_password(password)
print("SHA-256 hashed password is: ", hashed_password)