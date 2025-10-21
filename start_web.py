#!/usr/bin/env python3
"""
Script de démarrage pour l'interface web du scanner de sécurité
"""

import sys
import os

# Ajouter le répertoire courant au path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from webscan_reporter import run_web_server

if __name__ == '__main__':
    print("🚀 Démarrage du serveur web...")
    
    try:
        host = os.environ.get('HOST', '0.0.0.0')
        port = int(os.environ.get('PORT', 5000))
        print(f"📋 Interface disponible sur: http://{host}:{port}")
        print("🛑 Pour arrêter le serveur: Ctrl+C")
        print("-" * 50)
        run_web_server(host=host, port=port, debug=False)
    except KeyboardInterrupt:
        print("\n👋 Serveur arrêté. Au revoir !")
    except Exception as e:
        print(f"❌ Erreur: {e}")
        sys.exit(1)
