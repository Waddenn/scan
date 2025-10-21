#!/usr/bin/env python3
"""
Test du container Docker
"""

import subprocess
import time
import requests
import sys
import os

def test_docker_build():
    """Test la construction de l'image Docker"""
    print("🐳 Test de construction de l'image Docker...")
    
    try:
        result = subprocess.run([
            'docker', 'build', '-t', 'webscanner-test', '.'
        ], capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            print("✅ Image Docker construite avec succès")
            return True
        else:
            print(f"❌ Erreur de construction: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print("❌ Timeout lors de la construction")
        return False
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return False

def test_docker_run():
    """Test le lancement du container"""
    print("🚀 Test de lancement du container...")
    
    try:
        # Lancer le container en arrière-plan
        process = subprocess.Popen([
            'docker', 'run', '-d', '-p', '5000:5000', 
            '--name', 'webscanner-test-container',
            'webscanner-test'
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Attendre que le container démarre
        time.sleep(10)
        
        # Vérifier que le container fonctionne
        check_result = subprocess.run([
            'docker', 'ps', '--filter', 'name=webscanner-test-container', 
            '--format', '{{.Status}}'
        ], capture_output=True, text=True)
        
        if 'Up' in check_result.stdout:
            print("✅ Container lancé avec succès")
            return True
        else:
            print(f"❌ Container non démarré: {check_result.stdout}")
            return False
            
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return False

def test_web_interface():
    """Test l'interface web"""
    print("🌐 Test de l'interface web...")
    
    try:
        # Test de la page d'accueil
        response = requests.get('http://localhost:5000', timeout=10)
        if response.status_code == 200:
            print("✅ Interface web accessible")
            return True
        else:
            print(f"❌ Erreur interface web: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Erreur de connexion: {e}")
        return False

def cleanup():
    """Nettoyage des containers de test"""
    print("🧹 Nettoyage...")
    
    try:
        # Arrêter et supprimer le container
        subprocess.run(['docker', 'stop', 'webscanner-test-container'], 
                      capture_output=True)
        subprocess.run(['docker', 'rm', 'webscanner-test-container'], 
                      capture_output=True)
        
        # Supprimer l'image de test
        subprocess.run(['docker', 'rmi', 'webscanner-test'], 
                      capture_output=True)
        
        print("✅ Nettoyage terminé")
    except Exception as e:
        print(f"⚠️ Erreur lors du nettoyage: {e}")

def main():
    """Fonction principale de test"""
    print("🧪 Test complet du container Docker")
    print("=" * 50)
    
    success = True
    
    # Test 1: Construction
    if not test_docker_build():
        success = False
    
    # Test 2: Lancement
    if success and not test_docker_run():
        success = False
    
    # Test 3: Interface web
    if success and not test_web_interface():
        success = False
    
    # Nettoyage
    cleanup()
    
    if success:
        print("\n🎉 Tous les tests Docker sont passés !")
        print("🐳 Le container est prêt pour le déploiement")
    else:
        print("\n❌ Certains tests ont échoué")
        sys.exit(1)

if __name__ == '__main__':
    main()
