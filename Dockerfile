# Utiliser Python 3.13 slim comme image de base
FROM python:3.13-slim

# Métadonnées
LABEL maintainer="Web Security Scanner"
LABEL description="Web Security Scanner with Flask interface"
LABEL version="1.0"

# Variables d'environnement
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV FLASK_APP=webscan_reporter.py
ENV FLASK_ENV=production

# Créer un utilisateur non-root pour la sécurité
RUN groupadd -r scanner && useradd -r -g scanner scanner

# Installer les dépendances système
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Créer le répertoire de travail
WORKDIR /app

# Copier les fichiers de dépendances
COPY requirements.txt .

# Installer les dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code source
COPY webscan_reporter.py .
COPY start_web.py .
COPY templates/ templates/
COPY static/ static/

# Créer les répertoires nécessaires
RUN mkdir -p /app/reports && \
    chown -R scanner:scanner /app

# Changer vers l'utilisateur non-root
USER scanner

# Exposer le port
EXPOSE 5000

# Variables d'environnement pour le serveur
ENV HOST=0.0.0.0
ENV PORT=5000

# Commande de démarrage
CMD ["python", "start_web.py"]
