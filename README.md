# 🔍 Web Security Scanner

Un outil de scan de sécurité web moderne avec interface web intuitive, générant des rapports HTML détaillés.

## ✨ Fonctionnalités

- 🌐 **Interface web moderne** : Interface responsive et intuitive
- 📊 **Rapports détaillés** : Graphiques interactifs et analyses complètes
- 🔒 **Analyse de sécurité** : En-têtes HTTP, certificats SSL, redirections
- 📱 **Multi-plateforme** : Fonctionne sur desktop, mobile et tablette
- 🐳 **Containerisé** : Déploiement facile avec Docker

## 🚀 Démarrage rapide

### Option 1: Docker (Recommandé)

```bash
# Cloner le repository
git clone <votre-repo>
cd scan

# Construire et lancer avec Docker Compose
docker-compose up --build

# Ou avec Docker directement
docker build -t webscanner .
docker run -p 5000:5000 webscanner
```

**Accès :** http://localhost:5000

### Option 2: Installation locale

```bash
# Cloner le repository
git clone <votre-repo>
cd scan

# Créer l'environnement virtuel
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate    # Windows

# Installer les dépendances
pip install -r requirements.txt

# Lancer le serveur
python start_web.py
```

## 🐳 Docker

### Build local

```bash
# Construire l'image
docker build -t webscanner .

# Lancer le container
docker run -p 5000:5000 webscanner

# Avec variables d'environnement
docker run -p 5000:5000 \
  -e HOST=0.0.0.0 \
  -e PORT=5000 \
  webscanner
```

### Docker Compose

```bash
# Démarrage simple
docker-compose up

# En arrière-plan
docker-compose up -d

# Avec logs
docker-compose up --build

# Arrêt
docker-compose down
```

### Image du Registry GitHub

```bash
# Utiliser l'image du registry GitHub
docker run -p 5000:5000 \
  ghcr.io/your-username/your-repo:latest
```

## 📋 Utilisation

### Interface Web

1. Ouvrez http://localhost:5000
2. Entrez l'URL à analyser (ex: `example.com`)
3. Cliquez sur "Lancer l'analyse"
4. Consultez le rapport détaillé

### Ligne de commande

```bash
# Mode ligne de commande (comme avant)
python webscan_reporter.py --target example.com --output rapport.html

# Mode serveur web
python webscan_reporter.py --web
```

## 🔧 Configuration

### Variables d'environnement

- `HOST` : Adresse d'écoute (défaut: 0.0.0.0)
- `PORT` : Port d'écoute (défaut: 5000)
- `FLASK_ENV` : Environnement Flask (production/development)

### Ports

- **5000** : Interface web principale
- **5001** : Interface web (registry image)

## 📊 Rapports générés

- **Score de sécurité** : Évaluation basée sur les en-têtes HTTP
- **Certificat SSL** : Informations détaillées du certificat
- **En-têtes de sécurité** : Analyse des en-têtes de protection
- **Redirections** : Vérification HTTP → HTTPS
- **Recommandations** : Actions suggérées pour améliorer la sécurité

## 🛠️ Développement

### Structure du projet

```
scan/
├── webscan_reporter.py    # Script principal
├── start_web.py          # Démarrage serveur web
├── templates/            # Templates HTML
├── requirements.txt      # Dépendances Python
├── Dockerfile           # Configuration Docker
├── docker-compose.yml   # Orchestration Docker
└── .github/workflows/   # GitHub Actions
```

### Tests

```bash
# Test de l'interface web
python test_web.py

# Test des fonctionnalités
python webscan_reporter.py --self-test
```

## 🚀 Déploiement

### GitHub Actions

Le projet inclut des GitHub Actions pour :
- Build automatique de l'image Docker
- Push vers GitHub Container Registry
- Support multi-architecture (AMD64, ARM64)

### Production

Pour la production, utilisez un serveur WSGI :

```dockerfile
# Dockerfile.production
FROM python:3.13-slim
# ... configuration ...
RUN pip install gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "webscan_reporter:app"]
```

## 📄 Licence

MIT License - Voir le fichier LICENSE pour plus de détails.

## 🤝 Contribution

1. Fork le projet
2. Créez une branche feature (`git checkout -b feature/AmazingFeature`)
3. Commit vos changements (`git commit -m 'Add some AmazingFeature'`)
4. Push vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrez une Pull Request

## 📞 Support

- 🐛 **Bugs** : Ouvrez une issue sur GitHub
- 💡 **Suggestions** : Discussions GitHub
- 📧 **Contact** : Voir le profil GitHub

---

**🔍 Web Security Scanner** - Analysez la sécurité de vos sites web en quelques clics !
