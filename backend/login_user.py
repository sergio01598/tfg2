import requests

def login_user():
    url = "http://127.0.0.1:5000/login"
    headers = {"Content-Type": "application/json"}
    data = {
        "username": "nuevo_usuario",  # Utiliza el nombre de usuario que registraste
        "password": "mi_contraseña"    # Utiliza la contraseña correspondiente
    }

    response = requests.post(url, json=data, headers=headers)

    if response.status_code == 200:
        print("Login exitoso:", response.json())
    elif response.status_code == 401:
        print("Error: Credenciales incorrectas.")
    else:
        print("Error al iniciar sesión:", response.status_code, response.text)

if __name__ == "__main__":
    login_user()
