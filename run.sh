#!/bin/bash
# Script simple pour lancer le Web Security Scanner

echo "🔍 Web Security Scanner"
echo "======================"
echo ""

# Vérifier si Docker est installé
if ! command -v docker &> /dev/null; then
    echo "❌ Docker n'est pas installé"
    exit 1
fi

# Arrêter le container existant s'il existe
echo "🧹 Nettoyage des containers existants..."
docker stop webscanner 2>/dev/null || true
docker rm webscanner 2>/dev/null || true

# Lancer le nouveau container
echo "🚀 Lancement du Web Security Scanner..."
docker run -d -p 5000:5000 --name webscanner ghcr.io/waddenn/scan:latest

# Attendre que le service démarre
echo "⏳ Démarrage en cours..."
sleep 3

# Vérifier que le service fonctionne
if curl -f http://localhost:5000 > /dev/null 2>&1; then
    echo "✅ Service démarré avec succès !"
    echo ""
    echo "🌐 Interface web : http://localhost:5000"
    echo "🛑 Pour arrêter : docker stop webscanner"
    echo "📊 Pour voir les logs : docker logs webscanner"
else
    echo "❌ Erreur lors du démarrage"
    exit 1
fi
