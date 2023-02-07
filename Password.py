import hashlib

def check_password_strength(password):
    if len(password) < 8:
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.islower() for char in password):
        return False
    if not any(char in "!@#$%^&*" for char in password):
        return False
    return True

def hash_password(password):
    password_bytes = password.encode('utf-8')
    sha256 = hashlib.sha256()
    sha256.update(password_bytes)
    return sha256.hexdigest()

password = input("Entrer votre mot de passe : ")

while not check_password_strength(password):
    print("Le mot de passe n'est pas valide, veuillez réessayer. Pour rappelle il doit faire : 8 caractères, une majuscule, une minuscule, un chiffre et un caractère spécial")
    password = input("Entrer votre mot de passe : ")

print("Votre mot de passe est validé.")
print("Votre mot de passe crypté :", hash_password(password))