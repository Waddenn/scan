# 🌐 Interface Web - Web Security Scanner

## 🚀 Démarrage rapide

### 1. Lancer le serveur web
```bash
cd /home/tom/Dev/scan
./venv/bin/python start_web.py
```

### 2. Ouvrir dans le navigateur
Ouvrez votre navigateur et allez sur : **http://127.0.0.1:5000**

## ✨ Fonctionnalités

### 🎯 Interface intuitive
- **Formulaire simple** : Entrez une URL ou un domaine
- **Exemples rapides** : Cliquez sur les badges pour tester rapidement
- **Analyse en temps réel** : Barre de progression pendant l'analyse

### 📊 Rapports détaillés
- **Score de sécurité** : Graphique interactif avec explication
- **En-têtes de sécurité** : Liste détaillée avec statut
- **Certificat SSL** : Informations complètes
- **Recommandations** : Actions suggérées pour améliorer la sécurité

### 💾 Export des résultats
- **Rapport HTML** : Vue complète dans le navigateur
- **Téléchargement JSON** : Données brutes pour analyse

## 🔧 Utilisation

### Mode ligne de commande (comme avant)
```bash
./venv/bin/python webscan_reporter.py --target example.com --output rapport.html
```

### Mode interface web
```bash
./venv/bin/python webscan_reporter.py --web
# ou
./venv/bin/python start_web.py
```

## 🌟 Avantages de l'interface web

1. **Plus besoin de commandes** : Interface graphique intuitive
2. **Résultats instantanés** : Pas de fichiers à gérer
3. **Partage facile** : Liens directs vers les rapports
4. **Multi-utilisateurs** : Plusieurs personnes peuvent utiliser l'interface
5. **Mobile-friendly** : Responsive design

## 🛠️ Configuration

### Changer le port
Modifiez le port dans `start_web.py` :
```python
run_web_server(host='127.0.0.1', port=8080)  # Port 8080
```

### Accès réseau
Pour accéder depuis d'autres machines :
```python
run_web_server(host='0.0.0.0', port=5000)  # Accessible depuis le réseau
```

## 🔒 Sécurité

- Le serveur est en mode développement
- Pour la production, utilisez un serveur WSGI (gunicorn, uwsgi)
- Les rapports sont stockés temporairement en mémoire
- Redémarrez le serveur pour vider le cache

## 📱 Interface mobile

L'interface est entièrement responsive et fonctionne sur :
- 📱 Smartphones
- 📱 Tablettes  
- 💻 Ordinateurs
- 🖥️ Grands écrans
