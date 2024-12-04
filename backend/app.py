import os
from flask import Flask, jsonify, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Configuración de la base de datos y JWT
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///escaparate_artistico.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'secret-key'  # Cambia esto por una clave segura

# Configuración para subir archivos
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Inicializar la base de datos y JWT
db = SQLAlchemy(app)
jwt = JWTManager(app)
CORS(app)

# Modelo de Usuario
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)

# Modelo de Obra de Arte
class Artwork(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    artist = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    image_url = db.Column(db.String(200), nullable=False)

# Modelo de Votación
class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    artwork_id = db.Column(db.Integer, db.ForeignKey('artwork.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)

# Modelo de Mensaje
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    artwork_id = db.Column(db.Integer, db.ForeignKey('artwork.id'), nullable=False)
    sender_name = db.Column(db.String(100), nullable=False)
    sender_phone = db.Column(db.String(15), nullable=False)
    message = db.Column(db.Text, nullable=False)
    artist = db.Column(db.String(100), nullable=False)

# Crear todas las tablas si no existen
with app.app_context():
    db.create_all()

# Ruta principal para probar el servidor
@app.route('/')
def home():
    return "¡Bienvenido a Escaparate Artístico!"

# Endpoint para registrar un nuevo usuario
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data or 'username' not in data or 'password' not in data:
        return jsonify(message="El nombre de usuario y la contraseña son obligatorios"), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify(message="El nombre de usuario ya está en uso, por favor elige otro"), 409

    hashed_password = generate_password_hash(data['password'])
    new_user = User(username=data['username'], password=hashed_password, role='artist')
    db.session.add(new_user)
    db.session.commit()
    return jsonify(message="Usuario registrado con éxito"), 201

# Endpoint para iniciar sesión y obtener un token JWT
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or 'username' not in data or 'password' not in data:
        return jsonify(message="El nombre de usuario y la contraseña son obligatorios"), 400

    user = User.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity={'username': user.username, 'role': user.role})
        return jsonify(access_token=access_token), 200

    return jsonify(message="Credenciales incorrectas"), 401

# Endpoint para verificar el rol del usuario autenticado
@app.route('/user-role', methods=['GET'])
@jwt_required()
def get_user_role():
    current_user = get_jwt_identity()
    return jsonify(username=current_user['username'], role=current_user['role']), 200

# Endpoint para obtener todas las obras de arte (puede ser accedido por cualquiera)
@app.route('/artworks', methods=['GET'])
def get_artworks():
    artworks = Artwork.query.all()
    artworks_data = [
        {
            'id': art.id,
            'title': art.title,
            'artist': art.artist,
            'description': art.description,
            'image_url': f"http://127.0.0.1:5000/uploads/{os.path.basename(art.image_url)}",
            'average_score': round(db.session.query(db.func.avg(Vote.score)).filter_by(artwork_id=art.id).scalar() or 0, 2),
            'votes_count': Vote.query.filter_by(artwork_id=art.id).count()
        } for art in artworks
    ]
    return jsonify(artworks_data), 200


# Endpoint para obtener todas las obras de arte del usuario autenticado
@app.route('/my-artworks', methods=['GET'])
@jwt_required()
def get_my_artworks():
    current_user = get_jwt_identity()
    if current_user['role'] != 'artist':
        return jsonify(message="Acceso denegado. Solo los artistas pueden ver sus obras."), 403

    artworks = Artwork.query.filter_by(artist=current_user['username']).all()
    artworks_data = [
        {
            'id': art.id,
            'title': art.title,
            'artist': art.artist,
            'description': art.description,
            'image_url': f"http://127.0.0.1:5000/uploads/{os.path.basename(art.image_url)}",
            'average_score': db.session.query(db.func.avg(Vote.score)).filter_by(artwork_id=art.id).scalar(),
            'votes_count': Vote.query.filter_by(artwork_id=art.id).count()
        } for art in artworks
    ]
    return jsonify(artworks_data), 200

# Endpoint para añadir una nueva obra de arte (solo para artistas autenticados)
@app.route('/artworks', methods=['POST'])
@jwt_required()
def add_artwork():
    current_user = get_jwt_identity()

    if current_user['role'] != 'artist':
        return jsonify(message="Acceso denegado. Solo los artistas pueden añadir obras."), 403

    if not request.content_type.startswith('multipart/form-data'):
        return jsonify(message="Tipo de contenido incorrecto. Se requiere 'multipart/form-data'."), 400

    if 'image' not in request.files:
        return jsonify(message="Falta la imagen en la solicitud."), 400

    image = request.files['image']
    if image.filename == '':
        return jsonify(message="No se seleccionó ninguna imagen."), 400

    try:
        filename = secure_filename(image.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image.save(filepath)
    except Exception as e:
        return jsonify(message=f"Error al guardar la imagen: {str(e)}"), 500

    title = request.form.get('title')
    if not title:
        return jsonify(message="El título de la obra es obligatorio."), 400

    description = request.form.get('description', '')

    new_artwork = Artwork(title=title, artist=current_user['username'], description=description, image_url=filepath)
    try:
        db.session.add(new_artwork)
        db.session.commit()
        return jsonify({'message': 'Obra de arte añadida con éxito!'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify(message=f"Error al añadir la obra: {str(e)}"), 500

# Endpoint para votar por una obra de arte
@app.route('/artworks/<int:artwork_id>/vote', methods=['POST'])
def vote_artwork(artwork_id):
    data = request.get_json()

    if not data or 'score' not in data:
        return jsonify(message="Se requiere una puntuación"), 400

    score = data['score']
    if not (1 <= score <= 5):
        return jsonify(message="La puntuación debe estar entre 1 y 5"), 400

    artwork = Artwork.query.get(artwork_id)

    if not artwork:
        return jsonify(message="Obra de arte no encontrada."), 404

    new_vote = Vote(artwork_id=artwork_id, score=score)

    try:
        db.session.add(new_vote)
        db.session.commit()
        
        # Calcular el promedio actualizado
        average_score = db.session.query(db.func.avg(Vote.score)).filter_by(artwork_id=artwork_id).scalar()

        return jsonify({'message': 'Voto registrado con éxito', 'average_score': round(average_score, 2)}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify(message=f"Error al registrar el voto: {str(e)}"), 500


# Endpoint para enviar un mensaje al artista
@app.route('/artworks/<int:artwork_id>/contact', methods=['POST'])
def contact_artist(artwork_id):
    data = request.get_json()

    if not data or 'sender_name' not in data or 'sender_phone' not in data or 'message' not in data:
        return jsonify(message="Todos los campos (nombre, teléfono y mensaje) son obligatorios"), 400

    artwork = Artwork.query.get(artwork_id)
    if not artwork:
        return jsonify(message="Obra de arte no encontrada"), 404

    new_message = Message(artwork_id=artwork_id, sender_name=data['sender_name'], sender_phone=data['sender_phone'], message=data['message'], artist=artwork.artist)

    try:
        db.session.add(new_message)
        db.session.commit()
        return jsonify({'message': 'Mensaje enviado con éxito al artista'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify(message=f"Error al enviar el mensaje: {str(e)}"), 500

# Endpoint para que los artistas vean sus mensajes
@app.route('/messages', methods=['GET'])
@jwt_required()
def get_messages():
    current_user = get_jwt_identity()

    if current_user['role'] != 'artist':
        return jsonify(message="Acceso denegado. Solo los artistas pueden ver los mensajes."), 403

    messages = Message.query.filter_by(artist=current_user['username']).all()
    messages_data = [
        {
            'id': msg.id,
            'artwork_id': msg.artwork_id,
            'sender_name': msg.sender_name,
            'sender_phone': msg.sender_phone,
            'message': msg.message
        } for msg in messages
    ]
    return jsonify(messages_data), 200

# Endpoint para eliminar una obra de arte
@app.route('/artworks/<int:artwork_id>', methods=['DELETE'])
@jwt_required()
def delete_artwork(artwork_id):
    current_user = get_jwt_identity()
    artwork = Artwork.query.get(artwork_id)

    if not artwork:
        return jsonify(message="Obra de arte no encontrada."), 404

    if artwork.artist != current_user['username']:
        return jsonify(message="Acceso denegado. Solo el artista que subió la obra puede eliminarla."), 403

    try:
        if os.path.exists(artwork.image_url):
            os.remove(artwork.image_url)

        db.session.delete(artwork)
        db.session.commit()
        return jsonify({'message': 'Obra de arte eliminada con éxito!'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify(message=f"Error al eliminar la obra: {str(e)}"), 500

# Endpoint para servir archivos de imagen
@app.route('/uploads/<filename>', methods=['GET'])
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Endpoint para obtener notificaciones para el artista autenticado
@app.route('/notifications', methods=['GET'])
@jwt_required()
def get_notifications():
    current_user = get_jwt_identity()

    if current_user['role'] != 'artist':
        return jsonify(message="Acceso denegado. Solo los artistas pueden ver las notificaciones."), 403

    notifications = Message.query.filter_by(artist=current_user['username']).all()
    notifications_data = [
        {
            'id': notification.id,
            'artwork_id': notification.artwork_id,
            'sender_name': notification.sender_name,
            'sender_phone': notification.sender_phone,
            'message': notification.message
        } for notification in notifications
    ]
    return jsonify(notifications_data), 200

if __name__ == '__main__':
    app.run(debug=True)
