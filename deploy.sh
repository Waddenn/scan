#!/bin/bash
# Script de déploiement pour Web Security Scanner

set -e

echo "🚀 Déploiement de Web Security Scanner"
echo "======================================"

# Couleurs pour les messages
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Fonction pour afficher les messages
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Vérifier que Docker est installé
if ! command -v docker &> /dev/null; then
    log_error "Docker n'est pas installé. Veuillez l'installer d'abord."
    exit 1
fi

# Vérifier que Docker Compose est installé
if ! command -v docker-compose &> /dev/null; then
    log_warn "Docker Compose n'est pas installé. Installation en cours..."
    # Installation de docker-compose si nécessaire
fi

log_info "Construction de l'image Docker..."
docker build -t webscanner:latest .

log_info "Arrêt des containers existants..."
docker-compose down 2>/dev/null || true

log_info "Démarrage des services..."
docker-compose up -d

log_info "Vérification du statut..."
sleep 5

# Vérifier que le service fonctionne
if curl -f http://localhost:5000 > /dev/null 2>&1; then
    log_info "✅ Service démarré avec succès !"
    echo ""
    echo "🌐 Interface web disponible sur: http://localhost:5000"
    echo "📱 Interface mobile-friendly"
    echo "🔍 Prêt à scanner des sites web !"
    echo ""
    echo "Pour arrêter le service: docker-compose down"
    echo "Pour voir les logs: docker-compose logs -f"
else
    log_error "❌ Le service ne répond pas. Vérifiez les logs avec: docker-compose logs"
    exit 1
fi
