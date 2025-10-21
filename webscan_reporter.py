#!/usr/bin/env python3
"""
webscan_reporter.py

Petit outil de scan web "one-shot" qui produit un rapport HTML + JSON
objectif : checks pratiques pour sécuriser des services exposés sur Internet.

Usage:
    python3 webscan_reporter.py --target example.com --output report.html

Dépendances (pip):
    requests

Fonctionnalités:
 - Résolution DNS basique (A records)
 - Connexion TLS (protocol, cipher)
 - Extraction du certificat (issuer, subject, SANs, validité)
 - Vérification de l'en-tête HTTP(S) et des en-têtes de sécurité courants
 - Vérification redirection HTTP -> HTTPS
 - Existence de /robots.txt et /.well-known/security.txt
 - Petit score "security headers" et checklist de recommandations
 - Génère report.html (autonome) et report.json

Limites:
 - Ne remplace pas un audit approfondi (nmap, sslyze, testssl.sh, Qualys SSL Labs, etc.)
 - Ne teste pas toutes les vulnérabilités actives ni la configuration de serveurs/app (CSP fine-grained, OCSP stapling en détail, etc.)

Licence: MIT
"""

import argparse
import json
import socket
import ssl
import sys
import datetime
import urllib.parse
from collections import defaultdict
import os
import tempfile

import requests
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for


DEFAULT_TIMEOUT = 8

SECURITY_HEADERS = [
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy',
    'feature-policy',
]


def resolve_host(host):
    try:
        answers = socket.getaddrinfo(host, None)
        addrs = sorted({ai[4][0] for ai in answers})
        return addrs
    except Exception:
        return []


def fetch_http(url, timeout=DEFAULT_TIMEOUT, allow_redirects=True):
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=allow_redirects)
        return r
    except Exception:
        return None


def tls_probe(host, port=443, timeout=DEFAULT_TIMEOUT):
    info = {}
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                try:
                    cert = ssock.getpeercert()
                except Exception as e:
                    cert = {}
                    info['cert_error'] = str(e)
                
                try:
                    proto = ssock.version()
                except Exception:
                    proto = None
                try:
                    cipher = ssock.cipher()
                except Exception:
                    cipher = None

                info['protocol'] = proto
                info['cipher'] = cipher
                info['cert'] = cert
                return info
    except Exception as e:
        info['error'] = str(e)
        return info


def parse_cert_dates(cert):
    # cert from getpeercert() has 'notBefore' and 'notAfter' keys with "Jun  1 12:00:00 2024 GMT" style
    out = {}
    for k in ('notBefore', 'notAfter'):
        if k in cert:
            try:
                out[k] = datetime.datetime.strptime(cert[k], "%b %d %H:%M:%S %Y %Z")
            except Exception:
                try:
                    out[k] = datetime.datetime.strptime(cert[k], "%b %d %H:%M:%S %Y GMT")
                except Exception:
                    out[k] = cert[k]
        else:
            out[k] = None
    return out


def header_score(headers):
    present = {}
    count = 0
    for h in SECURITY_HEADERS:
        if h in headers:
            present[h] = headers.get(h)
            count += 1
        else:
            present[h] = None
    score = int((count / len(SECURITY_HEADERS)) * 100)
    return score, present


def generate_html_report(context, out_filename):
    # small standalone HTML with Chart.js from CDN
    html = f"""
<!doctype html>
<html lang=\"fr\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
  <title>Scan Report — {context['target_display']}</title>
  <link href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css\" rel=\"stylesheet\">
  <script src=\"https://cdn.jsdelivr.net/npm/chart.js\"></script>
  <style>
    body {{ padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }}
    .container {{ background: white; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); padding: 30px; }}
    .card {{ margin-bottom: 20px; border: none; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
    .card-body {{ padding: 20px; }}
    .card-title {{ color: #2c3e50; font-weight: 600; margin-bottom: 15px; }}
    pre {{ white-space: pre-wrap; word-break: break-word; background: #f8f9fa; padding: 10px; border-radius: 5px; font-size: 0.9em; }}
    .chart-container {{ height: 350px; width: 100%; position: relative; }}
    .table {{ margin-bottom: 0; }}
    .table th {{ background-color: #f8f9fa; font-weight: 600; }}
    .badge {{ font-size: 0.8em; }}
    .status-ok {{ color: #28a745; font-weight: bold; }}
    .status-warning {{ color: #ffc107; font-weight: bold; }}
    .status-error {{ color: #dc3545; font-weight: bold; }}
    h1 {{ color: #2c3e50; text-align: center; margin-bottom: 30px; }}
    .summary-stats {{ display: flex; justify-content: space-around; text-align: center; }}
    .stat-item {{ flex: 1; padding: 10px; }}
    .stat-value {{ font-size: 1.5em; font-weight: bold; color: #3498db; }}
    .stat-label {{ font-size: 0.9em; color: #7f8c8d; }}
    .security-headers-list {{ max-height: 200px; overflow-y: auto; }}
    .header-item {{ display: flex; align-items: center; padding: 5px 0; }}
    .header-item strong {{ font-size: 0.9em; color: #495057; }}
    .score-explanation {{ background: #e3f2fd; padding: 15px; border-radius: 8px; margin-top: 15px; }}
    .score-explanation h6 {{ color: #1976d2; margin-bottom: 10px; }}
    .score-explanation p {{ margin: 0; font-size: 0.9em; color: #424242; }}
    .chart-wrapper {{ display: flex; justify-content: center; align-items: center; min-height: 350px; }}
    .chart-container canvas {{ max-width: 100%; height: auto !important; }}
  </style>
</head>
<body>
<div class=\"container\">
  <h1 class=\"mb-3\">Rapport de sécurité — {context['target_display']}</h1>
  <p class=\"text-muted\">Généré le {datetime.datetime.now(datetime.timezone.utc).isoformat()}</p>

  <!-- Résumé en haut -->
  <div class=\"card mb-4\">
    <div class=\"card-body\">
      <div class=\"summary-stats\">
        <div class=\"stat-item\">
          <div class=\"stat-value\">{', '.join(context.get('ips') or ['—'])}</div>
          <div class=\"stat-label\">IP(s) résolues</div>
        </div>
        <div class=\"stat-item\">
          <div class=\"stat-value\">{context.get('http_status') or '—'}</div>
          <div class=\"stat-label\">Statut HTTP</div>
        </div>
        <div class=\"stat-item\">
          <div class=\"stat-value\">{context.get('tls', {}).get('protocol') or '—'}</div>
          <div class=\"stat-label\">Protocole TLS</div>
        </div>
        <div class=\"stat-item\">
          <div class=\"stat-value\">{context.get('header_score')}%</div>
          <div class=\"stat-label\">Score sécurité</div>
        </div>
      </div>
    </div>
  </div>

  <!-- Score de sécurité détaillé -->
  <div class=\"card mb-4\">
    <div class=\"card-body\">
      <h5 class=\"card-title\">📊 Score de sécurité détaillé</h5>
      <div class=\"row\">
        <div class=\"col-lg-7\">
          <div class=\"chart-container\">
            <canvas id=\"scoreChart\"></canvas>
          </div>
        </div>
        <div class=\"col-lg-5\">
          <h6 class=\"text-muted mb-3\">En-têtes de sécurité analysés :</h6>
          <div class=\"security-headers-list\">
            {generate_security_headers_list(context.get('headers_present', {}))}
          </div>
          <div class=\"score-explanation\">
            <h6>📈 Comment est calculé le score ?</h6>
            <p>Le score est basé sur la présence de {len(SECURITY_HEADERS)} en-têtes de sécurité essentiels. Chaque en-tête présent compte pour {int(100/len(SECURITY_HEADERS))}% du score total.</p>
            <p><strong>Score actuel : {context.get('header_score')}%</strong> ({sum(1 for h in SECURITY_HEADERS if context.get('headers_present', {}).get(h))}/{len(SECURITY_HEADERS)} en-têtes présents)</p>
          </div>
        </div>
      </div>
    </div>
  </div>

  <div class=\"row\">
    <div class=\"col-md-6\">
      <div class=\"card\">
        <div class=\"card-body\">
          <h5 class=\"card-title\">🔒 Certificat SSL</h5>
          <p><strong>Émis par:</strong> {context.get('cert_issuer') or '—'}</p>
          <p><strong>Sujet:</strong> {context.get('cert_subject') or '—'}</p>
          <p><strong>Valide du — au:</strong> {context.get('cert_notBefore') or '—'} → {context.get('cert_notAfter') or '—'}</p>
          <p><strong>SANs:</strong> {', '.join(context.get('cert_sans') or []) or '—'}</p>
        </div>
      </div>
    </div>
    
    <div class=\"col-md-6\">
      <div class=\"card\">
        <div class=\"card-body\">
          <h5 class=\"card-title\">✅ Checks rapides</h5>
          <ul class=\"list-unstyled\">
            <li class=\"mb-2\">Redirection HTTP → HTTPS: <span class=\"{'status-ok' if context.get('http_to_https') else 'status-error'}\">{'✓ OK' if context.get('http_to_https') else '✗ NON'}</span></li>
            <li class=\"mb-2\">/robots.txt: <span class=\"{'status-ok' if context.get('robots_exists') else 'status-warning'}\">{'✓ présent' if context.get('robots_exists') else '✗ absent'}</span></li>
            <li class=\"mb-2\">/.well-known/security.txt: <span class=\"{'status-ok' if context.get('securitytxt_exists') else 'status-warning'}\">{'✓ présent' if context.get('securitytxt_exists') else '✗ absent'}</span></li>
          </ul>
        </div>
      </div>
    </div>
  </div>

  <div class=\"card\">
    <div class=\"card-body\">
      <h5 class=\"card-title\">📋 En-têtes HTTP complets</h5>
      <p class=\"text-muted mb-3\">Tous les en-têtes HTTP retournés par le serveur</p>
      <table class=\"table table-sm table-striped\">
        <thead><tr><th>En-tête</th><th>Valeur</th></tr></thead>
        <tbody>
"""
    for k, v in sorted(context.get('headers', {}).items()):
        html += f"<tr><td>{k}</td><td><pre>{v}</pre></td></tr>\n"

    html += """
        </tbody>
      </table>
    </div>
  </div>

  <div class=\"card\">
    <div class=\"card-body\">
      <h5 class=\"card-title\">💡 Recommandations d'amélioration</h5>
      <p class=\"text-muted mb-3\">Actions suggérées pour améliorer la sécurité du site</p>
      <ol>
"""
    for r in context.get('recommendations', []):
        html += f"    <li>{r}</li>\n"

    html += f"""
      </ol>
    </div>
  </div>

  <footer class=\"text-muted mt-4 text-center\">
    <hr>
    <p><strong>🔍 webscan_reporter.py</strong> — Outil d'audit de sécurité web rapide</p>
    <p class=\"small\">Pour un audit approfondi, utilisez <code>testssl.sh</code>, <code>sslyze</code>, <code>Qualys SSL Labs</code>, ou <code>nmap</code></p>
  </footer>
</div>

<script>
const ctxData = {{ score: {context.get('header_score') or 0} }}
const cfg = {{
  type: 'doughnut',
  data: {{ 
    labels: ['En-têtes présents', 'En-têtes manquants'], 
    datasets: [{{
      data: [ctxData.score, 100-ctxData.score], 
      backgroundColor: ['#28a745', '#ffc107'],
      borderWidth: 2,
      borderColor: '#fff',
      hoverOffset: 8
    }}] 
  }},
  options: {{ 
    responsive: true, 
    maintainAspectRatio: false,
    layout: {{
      padding: {{
        top: 20,
        bottom: 20,
        left: 20,
        right: 20
      }}
    }},
    plugins: {{ 
      legend: {{ 
        position: 'bottom',
        labels: {{
          padding: 25,
          usePointStyle: true,
          font: {{ size: 14, weight: 'bold' }}
        }}
      }},
      tooltip: {{
        callbacks: {{
          label: function(context) {{
            return context.label + ': ' + context.parsed + '%';
          }}
        }},
        titleFont: {{ size: 14, weight: 'bold' }},
        bodyFont: {{ size: 13 }}
      }},
      title: {{
        display: true,
        text: 'Score de sécurité: ' + ctxData.score + '%',
        font: {{ size: 18, weight: 'bold' }},
        color: '#2c3e50',
        padding: {{ top: 10, bottom: 20 }}
      }}
    }},
    cutout: '50%',
    elements: {{
      arc: {{
        borderWidth: 3,
        borderColor: '#fff'
      }}
    }}
  }}
}};
const c = new Chart(document.getElementById('scoreChart'), cfg);
</script>
</body>
</html>
"""
    with open(out_filename, 'w', encoding='utf-8') as f:
        f.write(html)


def generate_security_headers_list(headers_present):
    """Génère la liste HTML des en-têtes de sécurité avec leur statut"""
    html = ""
    for header in SECURITY_HEADERS:
        status = headers_present.get(header)
        if status:
            html += f'<div class="header-item mb-2"><span class="badge bg-success me-2">✓</span><strong>{header}</strong></div>'
        else:
            html += f'<div class="header-item mb-2"><span class="badge bg-danger me-2">✗</span><strong>{header}</strong></div>'
    return html


def build_recommendations(context):
    recs = []
    headers = context.get('headers', {})
    # HSTS
    if 'strict-transport-security' not in headers:
        recs.append('Activer Strict-Transport-Security (HSTS) avec "max-age=31536000; includeSubDomains; preload" si approprié.')
    else:
        recs.append('HSTS présent — vérifier la valeur et envisager preload si possible.')
    # CSP
    if 'content-security-policy' not in headers:
        recs.append('Ajouter Content-Security-Policy pour réduire le risque XSS (commencer par policy permissive puis durcir).')
    # X-Frame
    if 'x-frame-options' not in headers:
        recs.append('Ajouter X-Frame-Options (SAMEORIGIN ou DENY) pour se protéger du clickjacking.')
    if 'x-content-type-options' not in headers:
        recs.append("Ajouter X-Content-Type-Options: nosniff pour empêcher l'interprétation de types MIME inattendus.")
    if 'referrer-policy' not in headers:
        recs.append('Ajouter Referrer-Policy (ex: no-referrer-when-downgrade ou strict-origin-when-cross-origin)')
    # cert validity
    if context.get('cert_notAfter'):
        try:
            notafter = datetime.datetime.fromisoformat(context['cert_notAfter'])
            days = (notafter - datetime.datetime.utcnow()).days
            if days < 30:
                recs.append(f"Le certificat expire dans {days} jours — prévoir renouvellement automatique (ACME) si ce n'est pas déjà en place).")
        except Exception:
            pass
    # general
    recs.append("Désactiver les bannières inutiles côté serveur (Server header) pour réduire la surface d'information.")
    recs.append('Vérifier OCSP Stapling / CRL et la chaîne complète du certificat.')
    recs.append("Pour un audit approfondi: exécuter testssl.sh, sslyze, et un scan Nmap à partir d'un point externe.")
    return recs


def run_self_tests():
    """Exécute quelques tests simples (pas de dépendances externes).
    - Test 1: example.com (HTTPS valide)
    - Test 2: neverssl.com (HTTP only → pas de redirection HTTPS attendue)
    Les tests sont tolérants aux variations réseau et n'échouent pas le script; ils rapportent OK/FAIL.
    """
    tests = []

    # Test 1: example.com
    try:
        ctx = defaultdict(lambda: None)
        host = 'example.com'
        url_https = f'https://{host}/'
        ctx['target_display'] = host
        ctx['ips'] = resolve_host(host)
        r = fetch_http(url_https, timeout=DEFAULT_TIMEOUT, allow_redirects=True)
        if r is not None:
            ctx['headers'] = {k.lower(): v for k, v in r.headers.items()}
        else:
            ctx['headers'] = {}
        tls = tls_probe(host)
        ctx['tls'] = tls
        score, _ = header_score(ctx['headers'])
        ok = isinstance(ctx['ips'], list) and 'protocol' in tls and isinstance(score, int)
        tests.append(("example.com", ok, {
            'ips': ctx['ips'], 'tls_protocol': tls.get('protocol'), 'header_score': score
        }))
    except Exception as e:
        tests.append(("example.com", False, {'error': str(e)}))

    # Test 2: neverssl.com (HTTP only)
    try:
        host = 'neverssl.com'
        url_http = f'http://{host}/'
        r_http = fetch_http(url_http, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
        http_to_https = False
        if r_http is not None and r_http.is_redirect:
            loc = r_http.headers.get('Location', '')
            if loc.startswith('https://'):
                http_to_https = True
        ok = (http_to_https is False)
        tests.append(("neverssl.com", ok, {'http_to_https': http_to_https, 'status': getattr(r_http, 'status_code', None)}))
    except Exception as e:
        tests.append(("neverssl.com", False, {'error': str(e)}))

    # Impression du rapport de tests
    print("\n===== SELF-TESTS =====")
    for name, ok, details in tests:
        print(f"[{ 'OK' if ok else 'FAIL' }] {name} -> {json.dumps(details, default=str)}")
    print("====================\n")


def main():
    parser = argparse.ArgumentParser(description='Web quick security scanner -> HTML + JSON report')
    parser.add_argument('--target', '-t', help='target domain or URL (ex: example.com or https://example.com)')
    parser.add_argument('--output', '-o', default='webscan-report.html')
    parser.add_argument('--json', default='webscan-report.json')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument('--self-test', action='store_true', help='exécuter des tests de fumée intégrés')
    args = parser.parse_args()

    if args.self_test:
        run_self_tests()
        # Si aucun target fourni, on s'arrête après les tests
        if not args.target:
            return

    if not args.target:
        print("Erreur: --target est requis (ex: --target example.com). Ou utilisez --self-test.", file=sys.stderr)
        sys.exit(2)

    raw = args.target
    if not raw.startswith('http://') and not raw.startswith('https://'):
        host = raw
        url_https = f'https://{raw}/'
        url_http = f'http://{raw}/'
    else:
        parsed = urllib.parse.urlparse(raw)
        host = parsed.hostname
        url_https = f'https://{host}/'
        url_http = f'http://{host}/'

    ctx = defaultdict(lambda: None)
    ctx['target_display'] = host
    ctx['ips'] = resolve_host(host)

    # HTTP(S) fetch
    r = fetch_http(url_https, timeout=args.timeout, allow_redirects=True)
    if r is not None:
        ctx['http_status'] = f"{r.status_code} {r.reason}"
        ctx['headers'] = {k.lower(): v for k, v in r.headers.items()}
    else:
        ctx['http_status'] = None
        ctx['headers'] = {}

    # HTTP -> HTTPS redirect check
    r_http = fetch_http(url_http, timeout=args.timeout, allow_redirects=False)
    ctx['http_to_https'] = False
    if r_http is not None and r_http.is_redirect:
        loc = r_http.headers.get('Location', '')
        if loc.startswith('https://'):
            ctx['http_to_https'] = True

    # TLS probe
    tls = tls_probe(host, 443, timeout=args.timeout)
    ctx['tls'] = tls
    cert = tls.get('cert') or {}
    
    # Si le certificat n'est pas récupéré via getpeercert(), essayons une approche alternative
    if not cert and 'cert_error' in tls:
        print(f"Erreur certificat: {tls['cert_error']}")
        # Essayons de récupérer le certificat via une requête HTTPS
        try:
            import ssl
            import urllib.request
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with urllib.request.urlopen(f'https://{host}', timeout=args.timeout, context=context) as response:
                cert = response.info().get('SSL-Certificate')
                if cert:
                    print("Certificat récupéré via urllib")
        except Exception as e:
            print(f"Impossible de récupérer le certificat: {e}")
    
    parsed = parse_cert_dates(cert) if cert else {}
    if isinstance(parsed.get('notAfter'), datetime.datetime):
        ctx['cert_notAfter'] = parsed['notAfter'].isoformat()
    else:
        ctx['cert_notAfter'] = parsed.get('notAfter')
    if isinstance(parsed.get('notBefore'), datetime.datetime):
        ctx['cert_notBefore'] = parsed['notBefore'].isoformat()
    else:
        ctx['cert_notBefore'] = parsed.get('notBefore')

    # cert subject & issuer
    subj = cert.get('subject', ())
    issuer = cert.get('issuer', ())

    def fmt_name(name_tuple):
        if not name_tuple:
            return None
        parts = []
        for t in name_tuple:
            for k, v in t:
                parts.append(f"{k}={v}")
        return ', '.join(parts)

    ctx['cert_subject'] = fmt_name(subj)
    ctx['cert_issuer'] = fmt_name(issuer)
    ctx['cert_sans'] = [v for k, v in cert.get('subjectAltName', []) if k.lower() == 'dns'] if cert else []

    # header score
    score, present = header_score(ctx['headers'])
    ctx['header_score'] = score
    ctx['headers_present'] = present

    # robots & security.txt
    try:
        ctx['robots_exists'] = requests.head(url_https + 'robots.txt', timeout=args.timeout).status_code == 200
    except Exception:
        ctx['robots_exists'] = False
    try:
        ctx['securitytxt_exists'] = requests.head(url_https + '.well-known/security.txt', timeout=args.timeout).status_code == 200
    except Exception:
        ctx['securitytxt_exists'] = False

    # recommendations
    ctx['recommendations'] = build_recommendations(ctx)

    # dump json
    out_json = args.json
    with open(out_json, 'w', encoding='utf-8') as jf:
        json.dump(ctx, jf, default=str, indent=2, ensure_ascii=False)

    # html
    generate_html_report(ctx, args.output)

    print(f"Report généré: {args.output}")
    print(f"JSON: {out_json}")


# Application Flask
app = Flask(__name__)
app.secret_key = 'webscan_secret_key_2024'

# Stockage temporaire des rapports
reports_storage = {}

def run_scan_analysis(target, timeout=DEFAULT_TIMEOUT):
    """Exécute l'analyse de sécurité et retourne les données"""
    raw = target
    if not raw.startswith('http://') and not raw.startswith('https://'):
        host = raw
        url_https = f'https://{raw}/'
        url_http = f'http://{raw}/'
    else:
        parsed = urllib.parse.urlparse(raw)
        host = parsed.hostname
        url_https = f'https://{host}/'
        url_http = f'http://{host}/'

    ctx = defaultdict(lambda: None)
    ctx['target_display'] = host
    ctx['ips'] = resolve_host(host)

    # HTTP(S) fetch
    r = fetch_http(url_https, timeout=timeout, allow_redirects=True)
    if r is not None:
        ctx['http_status'] = f"{r.status_code} {r.reason}"
        ctx['headers'] = {k.lower(): v for k, v in r.headers.items()}
    else:
        ctx['http_status'] = None
        ctx['headers'] = {}

    # HTTP -> HTTPS redirect check
    r_http = fetch_http(url_http, timeout=timeout, allow_redirects=False)
    ctx['http_to_https'] = False
    if r_http is not None and r_http.is_redirect:
        loc = r_http.headers.get('Location', '')
        if loc.startswith('https://'):
            ctx['http_to_https'] = True

    # TLS probe
    tls = tls_probe(host, 443, timeout=timeout)
    ctx['tls'] = tls
    cert = tls.get('cert') or {}
    
    parsed = parse_cert_dates(cert) if cert else {}
    if isinstance(parsed.get('notAfter'), datetime.datetime):
        ctx['cert_notAfter'] = parsed['notAfter'].isoformat()
    else:
        ctx['cert_notAfter'] = parsed.get('notAfter')
    if isinstance(parsed.get('notBefore'), datetime.datetime):
        ctx['cert_notBefore'] = parsed['notBefore'].isoformat()
    else:
        ctx['cert_notBefore'] = parsed.get('notBefore')

    # cert subject & issuer
    subj = cert.get('subject', ())
    issuer = cert.get('issuer', ())

    def fmt_name(name_tuple):
        if not name_tuple:
            return None
        parts = []
        for t in name_tuple:
            for k, v in t:
                parts.append(f"{k}={v}")
        return ', '.join(parts)

    ctx['cert_subject'] = fmt_name(subj)
    ctx['cert_issuer'] = fmt_name(issuer)
    ctx['cert_sans'] = [v for k, v in cert.get('subjectAltName', []) if k.lower() == 'dns'] if cert else []

    # header score
    score, present = header_score(ctx['headers'])
    ctx['header_score'] = score
    ctx['headers_present'] = present

    # robots & security.txt
    try:
        ctx['robots_exists'] = requests.head(url_https + 'robots.txt', timeout=timeout).status_code == 200
    except Exception:
        ctx['robots_exists'] = False
    try:
        ctx['securitytxt_exists'] = requests.head(url_https + '.well-known/security.txt', timeout=timeout).status_code == 200
    except Exception:
        ctx['securitytxt_exists'] = False

    # recommendations
    ctx['recommendations'] = build_recommendations(ctx)
    
    return ctx

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        
        if not target:
            return jsonify({'error': 'URL cible requise'}), 400
        
        # Exécuter l'analyse
        ctx = run_scan_analysis(target)
        
        # Générer un ID unique pour le rapport
        import uuid
        report_id = str(uuid.uuid4())
        
        # Stocker le rapport
        reports_storage[report_id] = ctx
        
        return jsonify({
            'success': True,
            'target_display': ctx['target_display'],
            'report_id': report_id,
            'score': ctx['header_score']
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/report/<report_id>')
def view_report(report_id):
    if report_id not in reports_storage:
        return "Rapport non trouvé", 404
    
    ctx = reports_storage[report_id]
    
    # Générer le HTML du rapport
    html_content = generate_html_report_content(ctx)
    
    return html_content

@app.route('/download/<report_id>')
def download_json(report_id):
    if report_id not in reports_storage:
        return "Rapport non trouvé", 404
    
    ctx = reports_storage[report_id]
    
    # Créer un fichier JSON temporaire
    import tempfile
    import os
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as f:
        json.dump(ctx, f, default=str, indent=2, ensure_ascii=False)
        temp_file = f.name
    
    return send_file(temp_file, as_attachment=True, download_name=f'webscan-{ctx["target_display"]}.json')

def generate_html_report_content(context):
    """Génère le contenu HTML du rapport (version simplifiée pour Flask)"""
    html = f"""
<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Scan Report — {context['target_display']}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    body {{ padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }}
    .container {{ background: white; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); padding: 30px; }}
    .card {{ margin-bottom: 20px; border: none; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
    .card-body {{ padding: 20px; }}
    .card-title {{ color: #2c3e50; font-weight: 600; margin-bottom: 15px; }}
    pre {{ white-space: pre-wrap; word-break: break-word; background: #f8f9fa; padding: 10px; border-radius: 5px; font-size: 0.9em; }}
    .chart-container {{ height: 350px; width: 100%; position: relative; }}
    .table {{ margin-bottom: 0; }}
    .table th {{ background-color: #f8f9fa; font-weight: 600; }}
    .badge {{ font-size: 0.8em; }}
    .status-ok {{ color: #28a745; font-weight: bold; }}
    .status-warning {{ color: #ffc107; font-weight: bold; }}
    .status-error {{ color: #dc3545; font-weight: bold; }}
    h1 {{ color: #2c3e50; text-align: center; margin-bottom: 30px; }}
    .summary-stats {{ display: flex; justify-content: space-around; text-align: center; }}
    .stat-item {{ flex: 1; padding: 10px; }}
    .stat-value {{ font-size: 1.5em; font-weight: bold; color: #3498db; }}
    .stat-label {{ font-size: 0.9em; color: #7f8c8d; }}
    .security-headers-list {{ max-height: 200px; overflow-y: auto; }}
    .header-item {{ display: flex; align-items: center; padding: 5px 0; }}
    .header-item strong {{ font-size: 0.9em; color: #495057; }}
    .score-explanation {{ background: #e3f2fd; padding: 15px; border-radius: 8px; margin-top: 15px; }}
    .score-explanation h6 {{ color: #1976d2; margin-bottom: 10px; }}
    .score-explanation p {{ margin: 0; font-size: 0.9em; color: #424242; }}
    .chart-wrapper {{ display: flex; justify-content: center; align-items: center; min-height: 350px; }}
    .chart-container canvas {{ max-width: 100%; height: auto !important; }}
  </style>
</head>
<body>
<div class="container">
  <h1 class="mb-3">Rapport de sécurité — {context['target_display']}</h1>
  <p class="text-muted">Généré le {datetime.datetime.now(datetime.timezone.utc).isoformat()}</p>

  <!-- Résumé en haut -->
  <div class="card mb-4">
    <div class="card-body">
      <div class="summary-stats">
        <div class="stat-item">
          <div class="stat-value">{', '.join(context.get('ips') or ['—'])}</div>
          <div class="stat-label">IP(s) résolues</div>
        </div>
        <div class="stat-item">
          <div class="stat-value">{context.get('http_status') or '—'}</div>
          <div class="stat-label">Statut HTTP</div>
        </div>
        <div class="stat-item">
          <div class="stat-value">{context.get('tls', {}).get('protocol') or '—'}</div>
          <div class="stat-label">Protocole TLS</div>
        </div>
        <div class="stat-item">
          <div class="stat-value">{context.get('header_score')}%</div>
          <div class="stat-label">Score sécurité</div>
        </div>
      </div>
    </div>
  </div>

  <!-- Score de sécurité détaillé -->
  <div class="card mb-4">
    <div class="card-body">
      <h5 class="card-title">📊 Score de sécurité détaillé</h5>
      <div class="row">
        <div class="col-lg-7">
          <div class="chart-container">
            <canvas id="scoreChart"></canvas>
          </div>
        </div>
        <div class="col-lg-5">
          <h6 class="text-muted mb-3">En-têtes de sécurité analysés :</h6>
          <div class="security-headers-list">
            {generate_security_headers_list(context.get('headers_present', {}))}
          </div>
          <div class="score-explanation">
            <h6>📈 Comment est calculé le score ?</h6>
            <p>Le score est basé sur la présence de {len(SECURITY_HEADERS)} en-têtes de sécurité essentiels. Chaque en-tête présent compte pour {int(100/len(SECURITY_HEADERS))}% du score total.</p>
            <p><strong>Score actuel : {context.get('header_score')}%</strong> ({sum(1 for h in SECURITY_HEADERS if context.get('headers_present', {}).get(h))}/{len(SECURITY_HEADERS)} en-têtes présents)</p>
          </div>
        </div>
      </div>
    </div>
  </div>

  <div class="row">
    <div class="col-md-6">
      <div class="card">
        <div class="card-body">
          <h5 class="card-title">🔒 Certificat SSL</h5>
          <p><strong>Émis par:</strong> {context.get('cert_issuer') or '—'}</p>
          <p><strong>Sujet:</strong> {context.get('cert_subject') or '—'}</p>
          <p><strong>Valide du — au:</strong> {context.get('cert_notBefore') or '—'} → {context.get('cert_notAfter') or '—'}</p>
          <p><strong>SANs:</strong> {', '.join(context.get('cert_sans') or []) or '—'}</p>
        </div>
      </div>
    </div>
    
    <div class="col-md-6">
      <div class="card">
        <div class="card-body">
          <h5 class="card-title">✅ Checks rapides</h5>
          <ul class="list-unstyled">
            <li class="mb-2">Redirection HTTP → HTTPS: <span class="{'status-ok' if context.get('http_to_https') else 'status-error'}">{'✓ OK' if context.get('http_to_https') else '✗ NON'}</span></li>
            <li class="mb-2">/robots.txt: <span class="{'status-ok' if context.get('robots_exists') else 'status-warning'}">{'✓ présent' if context.get('robots_exists') else '✗ absent'}</span></li>
            <li class="mb-2">/.well-known/security.txt: <span class="{'status-ok' if context.get('securitytxt_exists') else 'status-warning'}">{'✓ présent' if context.get('securitytxt_exists') else '✗ absent'}</span></li>
          </ul>
        </div>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-body">
      <h5 class="card-title">📋 En-têtes HTTP complets</h5>
      <p class="text-muted mb-3">Tous les en-têtes HTTP retournés par le serveur</p>
      <table class="table table-sm table-striped">
        <thead><tr><th>En-tête</th><th>Valeur</th></tr></thead>
        <tbody>
"""
    for k, v in sorted(context.get('headers', {}).items()):
        html += f"<tr><td>{k}</td><td><pre>{v}</pre></td></tr>\n"

    html += """
        </tbody>
      </table>
    </div>
  </div>

  <div class="card">
    <div class="card-body">
      <h5 class="card-title">💡 Recommandations d'amélioration</h5>
      <p class="text-muted mb-3">Actions suggérées pour améliorer la sécurité du site</p>
      <ol>
"""
    for r in context.get('recommendations', []):
        html += f"    <li>{r}</li>\n"

    html += f"""
      </ol>
    </div>
  </div>

  <footer class="text-muted mt-4 text-center">
    <hr>
    <p><strong>🔍 webscan_reporter.py</strong> — Outil d'audit de sécurité web rapide</p>
    <p class="small">Pour un audit approfondi, utilisez <code>testssl.sh</code>, <code>sslyze</code>, <code>Qualys SSL Labs</code>, ou <code>nmap</code></p>
  </footer>
</div>

<script>
const ctxData = {{ score: {context.get('header_score') or 0} }}
const cfg = {{
  type: 'doughnut',
  data: {{ 
    labels: ['En-têtes présents', 'En-têtes manquants'], 
    datasets: [{{
      data: [ctxData.score, 100-ctxData.score], 
      backgroundColor: ['#28a745', '#ffc107'],
      borderWidth: 2,
      borderColor: '#fff',
      hoverOffset: 8
    }}] 
  }},
  options: {{ 
    responsive: true, 
    maintainAspectRatio: false,
    layout: {{
      padding: {{
        top: 20,
        bottom: 20,
        left: 20,
        right: 20
      }}
    }},
    plugins: {{ 
      legend: {{ 
        position: 'bottom',
        labels: {{
          padding: 25,
          usePointStyle: true,
          font: {{ size: 14, weight: 'bold' }}
        }}
      }},
      tooltip: {{
        callbacks: {{
          label: function(context) {{
            return context.label + ': ' + context.parsed + '%';
          }}
        }},
        titleFont: {{ size: 14, weight: 'bold' }},
        bodyFont: {{ size: 13 }}
      }},
      title: {{
        display: true,
        text: 'Score de sécurité: ' + ctxData.score + '%',
        font: {{ size: 18, weight: 'bold' }},
        color: '#2c3e50',
        padding: {{ top: 10, bottom: 20 }}
      }}
    }},
    cutout: '50%',
    elements: {{
      arc: {{
        borderWidth: 3,
        borderColor: '#fff'
      }}
    }}
  }}
}};
const c = new Chart(document.getElementById('scoreChart'), cfg);
</script>
</body>
</html>
"""
    return html

def run_web_server(host='127.0.0.1', port=5000, debug=False):
    """Lance le serveur web Flask"""
    print(f"🌐 Serveur web démarré sur http://{host}:{port}")
    print("📱 Ouvrez votre navigateur et accédez à l'URL ci-dessus")
    print("🔍 Vous pouvez maintenant scanner des sites directement depuis l'interface web")
    app.run(host=host, port=port, debug=debug)

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == '--web':
        # Mode serveur web
        run_web_server()
    else:
        # Mode ligne de commande (comme avant)
        main()
