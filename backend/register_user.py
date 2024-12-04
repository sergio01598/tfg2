import requests

def register_user():
    url = "http://127.0.0.1:5000/register"
    headers = {"Content-Type": "application/json"}
    data = {
        "username": "nacho",  # Cambia "nuevo_usuario" por cualquier nombre de usuario que desees probar
        "password": "nacho"    # Cambia "mi_contraseña" por una contraseña deseada
    }

    response = requests.post(url, json=data, headers=headers)

    if response.status_code == 201:
        print("Usuario registrado con éxito:", response.json())
    elif response.status_code == 409:
        print("Error: El nombre de usuario ya está en uso.")
    else:
        print("Error al registrar el usuario:", response.status_code, response.text)

if __name__ == "__main__":
    register_user()
