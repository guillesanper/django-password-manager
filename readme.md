## Django Password Manager

Este proyecto es un gestor de contraseñas web desarrollado con Django. Permite a los usuarios almacenar, cifrar y gestionar contraseñas y archivos de manera segura.

### Características principales
- Registro y autenticación de usuarios
- Almacenamiento seguro de contraseñas
- Cifrado de archivos y contraseñas
- Generador de contraseñas seguras
- Interfaz web moderna y responsiva

### Requisitos previos
- Python 3.10 o superior
- pip

### Instalación y ejecución local
1. Clona el repositorio:
   ```bash
   git clone https://github.com/guillesanper/django-password-manager.git
   cd django-password-manager
   ```
2. Instala las dependencias:
   ```bash
   pip install -r requirements.txt
   ```
3. Aplica las migraciones:
   ```bash
   python manage.py migrate
   ```
4. (Opcional) Crea un superusuario para acceder al panel de administración:
   ```bash
   python manage.py createsuperuser
   ```
5. Ejecuta el servidor de desarrollo:
   ```bash
   python manage.py runserver
   ```
6. Abre tu navegador y accede a:
   ```
   http://127.0.0.1:8000/
   ```

### Estructura principal del proyecto
- `myapp/`: Lógica principal de la aplicación
- `media/`: Archivos cifrados subidos por los usuarios
- `staticfiles/`: Archivos estáticos (CSS, JS, imágenes)
- `templates/`: Plantillas HTML

---
Para dudas o sugerencias, contacta al autor o abre un issue en el repositorio.
