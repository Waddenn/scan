# Changelog

Toutes les modifications notables de ce projet seront documentées dans ce fichier.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
et ce projet adhère au [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-10-21

### Added
- Interface web moderne et responsive
- Scanner de sécurité web complet
- Analyse des en-têtes HTTP de sécurité
- Vérification des certificats SSL
- Rapports HTML détaillés avec graphiques
- Support Docker et Docker Compose
- GitHub Actions pour CI/CD
- Support multi-architecture (AMD64, ARM64)
- Interface mobile-friendly
- Export des résultats en JSON
- Recommandations de sécurité automatiques

### Features
- **Interface web** : Interface intuitive accessible via navigateur
- **Analyse complète** : En-têtes, certificats, redirections, robots.txt
- **Rapports visuels** : Graphiques interactifs et scores de sécurité
- **Docker ready** : Containerisation complète avec Docker
- **CI/CD** : GitHub Actions pour build et déploiement automatique
- **Multi-plateforme** : Support desktop, mobile et tablette

### Technical
- Python 3.13 avec Flask
- Bootstrap 5.3.2 pour l'interface
- Chart.js pour les graphiques
- Docker multi-stage build
- GitHub Container Registry
- Health checks intégrés
- Sécurité renforcée (utilisateur non-root)

### Security
- Utilisateur non-root dans le container
- Validation des entrées utilisateur
- Gestion sécurisée des erreurs
- Headers de sécurité recommandés
