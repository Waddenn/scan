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
    try:
        host = os.environ.get('HOST', '0.0.0.0')
        port = int(os.environ.get('PORT', 5000))
        run_web_server(host=host, port=port, debug=False)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
