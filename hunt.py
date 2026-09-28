#!/data/data/com.termux/files/usr/bin/python
"""
HUNT — Bug Bounty Command Center
Sistema de gestão de caça: alvos, superfície, fila de testes,
diário, relatórios e estatísticas. Tudo offline, tudo teu.

Uso ético: gerencia APENAS caças autorizadas (bounty com escopo,
contrato, lab). O sistema registra contexto de autorização.
"""

import sqlite3
import json
import os
import sys
import time
import re
import hashlib
import html as html_mod
import argparse
from datetime import datetime, timedelta
from pathlib import Path

# ═══════════════════════════════════════════
#  PATHS & CORE
# ═══════════════════════════════════════════

VERSION = "1.0"
BASE = Path(__file__).resolve().parent
DB_PATH = BASE / "hunt.db"

GREEN = '\033[0;32m'
RED = '\033[0;31m'
YELLOW = '\033[1;33m'
CYAN = '\033[0;36m'
MAGENTA = '\033[0;35m'
GRAY = '\033[0;90m'
BOLD = '\033[1m'
NC = '\033[0m'


def get_db():
    """Conexão com o banco, com foreign keys ativas"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """Cria o schema completo"""
    db = get_db()
    db.executescript("""
    -- ═══ HUNTS: cada programa/alvo autorizado ═══
    CREATE TABLE IF NOT EXISTS hunts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        platform TEXT DEFAULT 'manual',   -- hackerone, bugcrowd, manual...
        scope TEXT DEFAULT '',             -- o que tá permitido testar
        out_of_scope TEXT DEFAULT '',      -- o que NÃO é permitido
        auth_url TEXT DEFAULT '',          -- link da policy/contrato
        bounty_min REAL DEFAULT 0,         -- bounty mínimo do programa
        bounty_max REAL DEFAULT 0,
        status TEXT DEFAULT 'active',      -- active, paused, done, dropped
        started_at TEXT DEFAULT (datetime('now')),
        notes TEXT DEFAULT ''
    );

    -- ═══ ASSETS: a superfície descoberta ═══
    CREATE TABLE IF NOT EXISTS assets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hunt_id INTEGER NOT NULL,
        type TEXT NOT NULL,               -- domain, subdomain, url, ip, endpoint
        value TEXT NOT NULL,
        source TEXT DEFAULT 'manual',     -- recon_tool, gobuster, manual...
        tech TEXT DEFAULT '',             -- wordpress, nginx, react...
        status_code INTEGER,
        priority INTEGER DEFAULT 5,       -- 1-10, 10 = teste primeiro
        tested INTEGER DEFAULT 0,         -- 0 não, 1 sim
        UNIQUE(hunt_id, type, value),
        FOREIGN KEY (hunt_id) REFERENCES hunts(id) ON DELETE CASCADE
    );

    -- ═══ FINDINGS: o que foi achado ═══
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hunt_id INTEGER NOT NULL,
        asset_id INTEGER,
        type TEXT NOT NULL,               -- sqli, xss, ssrf, idor, info...
        severity TEXT DEFAULT 'medium',   -- critical, high, medium, low, info
        title TEXT NOT NULL,
        description TEXT DEFAULT '',
        evidence TEXT DEFAULT '',         -- request/response, payload usado
        status TEXT DEFAULT 'draft',      -- draft, reported, triaged, accepted,
                                          -- paid, duplicate, n/a
        bounty REAL DEFAULT 0,
        found_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (hunt_id) REFERENCES hunts(id) ON DELETE CASCADE,
        FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE SET NULL
    );

    -- ═══ LOG: diário de caça ═══
    CREATE TABLE IF NOT EXISTS hunt_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hunt_id INTEGER NOT NULL,
        action TEXT NOT NULL,             -- o que fez
        detail TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (hunt_id) REFERENCES hunts(id) ON DELETE CASCADE
    );

    -- ═══ ÍNDICES pra busca rápida ═══
    CREATE INDEX IF NOT EXISTS idx_assets_hunt ON assets(hunt_id);
    CREATE INDEX IF NOT EXISTS idx_assets_priority ON assets(priority DESC);
    CREATE INDEX IF NOT EXISTS idx_assets_tested ON assets(tested);
    CREATE INDEX IF NOT EXISTS idx_findings_hunt ON findings(hunt_id);
    CREATE INDEX IF NOT EXISTS idx_log_hunt ON hunt_log(hunt_id);
    """)
    db.commit()
    db.close()


# ═══════════════════════════════════════════
#  MODELS — operações de cada tabela
# ═══════════════════════════════════════════

class Hunt:
    @staticmethod
    def create(name, platform='manual', scope='', oos='', auth_url='',
               bounty_min=0, bounty_max=0):
        db = get_db()
        try:
            db.execute(
                """INSERT INTO hunts (name, platform, scope, out_of_scope,
                   auth_url, bounty_min, bounty_max) VALUES (?,?,?,?,?,?,?)""",
                (name, platform, scope, oos, auth_url, bounty_min, bounty_max))
            db.commit()
            hunt_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
            Log.add(hunt_id, "hunt criado", f"platform={platform}")
            return hunt_id
        except sqlite3.IntegrityError:
            return None
        finally:
            db.close()

    @staticmethod
    def get(hunt_id):
        db = get_db()
        row = db.execute("SELECT * FROM hunts WHERE id=? OR name=?",
                        (hunt_id, str(hunt_id))).fetchone()
        db.close()
        return dict(row) if row else None

    @staticmethod
    def list(status=None):
        db = get_db()
        if status:
            rows = db.execute(
                "SELECT * FROM hunts WHERE status=? ORDER BY started_at DESC",
                (status,)).fetchall()
        else:
            rows = db.execute(
                "SELECT * FROM hunts ORDER BY started_at DESC").fetchall()
        db.close()
        return [dict(r) for r in rows]

    @staticmethod
    def update_status(hunt_id, status):
        db = get_db()
        db.execute("UPDATE hunts SET status=? WHERE id=? OR name=?",
                  (status, hunt_id, str(hunt_id)))
        db.commit()
        db.close()

    @staticmethod
    def delete(hunt_id):
        db = get_db()
        db.execute("DELETE FROM hunts WHERE id=? OR name=?",
                  (hunt_id, str(hunt_id)))
        db.commit()
        db.close()


class Asset:
    @staticmethod
    def add(hunt_id, atype, value, source='manual', tech='',
            status_code=None, priority=5):
        db = get_db()
        try:
            db.execute(
                """INSERT INTO assets (hunt_id, type, value, source,
                   tech, status_code, priority) VALUES (?,?,?,?,?,?,?)""",
                (hunt_id, atype, value, source, tech, status_code, priority))
            db.commit()
            return True
        except sqlite3.IntegrityError:
            return False  # já existe
        finally:
            db.close()

    @staticmethod
    def bulk_add(hunt_id, atype, values, source='manual', priority=5):
        """Importa lista (do recon_tool, gobuster, etc)"""
        db = get_db()
        added = 0
        for v in values:
            v = v.strip()
            if not v:
                continue
            try:
                db.execute(
                    """INSERT INTO assets (hunt_id, type, value, source,
                       priority) VALUES (?,?,?,?,?)""",
                    (hunt_id, atype, v, source, priority))
                added += 1
            except sqlite3.IntegrityError:
                pass
        db.commit()
        db.close()
        return added

    @staticmethod
    def queue(hunt_id, only_untested=True):
        """Fila de testes: prioridade DESC, não testados primeiro"""
        db = get_db()
        where = "WHERE hunt_id=?"
        params = [hunt_id]
        if only_untested:
            where += " AND tested=0"
        rows = db.execute(
            f"""SELECT * FROM assets {where}
                ORDER BY priority DESC, id ASC""",
            params).fetchall()
        db.close()
        return [dict(r) for r in rows]

    @staticmethod
    def mark_tested(asset_id, priority_new=None):
        db = get_db()
        if priority_new:
            db.execute("UPDATE assets SET tested=1, priority=? WHERE id=?",
                      (priority_new, asset_id))
        else:
            db.execute("UPDATE assets SET tested=1 WHERE id=?", (asset_id,))
        db.commit()
        db.close()

    @staticmethod
    def set_priority(asset_id, priority):
        db = get_db()
        db.execute("UPDATE assets SET priority=? WHERE id=?",
                  (priority, asset_id))
        db.commit()
        db.close()

    @staticmethod
    def stats(hunt_id):
        db = get_db()
        total = db.execute(
            "SELECT COUNT(*) FROM assets WHERE hunt_id=?",
            (hunt_id,)).fetchone()[0]
        tested = db.execute(
            "SELECT COUNT(*) FROM assets WHERE hunt_id=? AND tested=1",
            (hunt_id,)).fetchone()[0]
        by_type = db.execute(
            """SELECT type, COUNT(*) as n FROM assets WHERE hunt_id=?
               GROUP BY type ORDER BY n DESC""",
            (hunt_id,)).fetchall()
        by_tech = db.execute(
            """SELECT tech, COUNT(*) as n FROM assets WHERE hunt_id=?
               AND tech != '' GROUP BY tech ORDER BY n DESC""",
            (hunt_id,)).fetchall()
        db.close()
        return {
            'total': total, 'tested': tested,
            'pending': total - tested,
            'by_type': [dict(r) for r in by_type],
            'by_tech': [dict(r) for r in by_tech],
        }


class Finding:
    @staticmethod
    def add(hunt_id, ftype, title, severity='medium',
            asset_id=None, description='', evidence=''):
        db = get_db()
        db.execute(
            """INSERT INTO findings (hunt_id, asset_id, type, severity,
               title, description, evidence) VALUES (?,?,?,?,?,?,?)""",
            (hunt_id, asset_id, ftype, severity, title, description,
             evidence))
        db.commit()
        fid = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        db.close()
        return fid

    @staticmethod
    def list(hunt_id, status=None):
        db = get_db()
        if status:
            rows = db.execute(
                """SELECT * FROM findings WHERE hunt_id=? AND status=?
                   ORDER BY found_at DESC""",
                (hunt_id, status)).fetchall()
        else:
            rows = db.execute(
                """SELECT * FROM findings WHERE hunt_id=?
                   ORDER BY found_at DESC""",
                (hunt_id,)).fetchall()
        db.close()
        return [dict(r) for r in rows]

    @staticmethod
    def update_status(fid, status, bounty=None):
        db = get_db()
        if bounty is not None:
            db.execute("UPDATE findings SET status=?, bounty=? WHERE id=?",
                      (status, bounty, fid))
        else:
            db.execute("UPDATE findings SET status=? WHERE id=?",
                      (status, fid))
        db.commit()
        db.close()

    @staticmethod
    def total_bounty(hunt_id):
        db = get_db()
        row = db.execute(
            "SELECT SUM(bounty) FROM findings WHERE hunt_id=? AND bounty>0",
            (hunt_id,)).fetchone()
        db.close()
        return row[0] or 0


class Log:
    @staticmethod
    def add(hunt_id, action, detail=''):
        db = get_db()
        db.execute(
            "INSERT INTO hunt_log (hunt_id, action, detail) VALUES (?,?,?)",
            (hunt_id, action, detail))
        db.commit()
        db.close()

    @staticmethod
    def tail(hunt_id, limit=20):
        db = get_db()
        rows = db.execute(
            """SELECT * FROM hunt_log WHERE hunt_id=?
               ORDER BY created_at DESC LIMIT ?""",
            (hunt_id, limit)).fetchall()
        db.close()
        return [dict(r) for r in rows]





# ═══════════════════════════════════════════
#  IMPORTADOR
# ═══════════════════════════════════════════

class Importer:
    TECH_PRIORITY = {
        'wordpress': 8, 'drupal': 8, 'joomla': 8,
        'struts': 10, 'weblogic': 10, 'jenkins': 9,
        'tomcat': 8, 'glassfish': 8,
        'react': 5, 'vue': 5, 'angular': 5, 'next.js': 5,
        'django': 6, 'laravel': 6, 'flask': 6, 'express': 6,
        'nginx': 4, 'apache': 4, 'iis': 5,
        'cloudflare': 2, 'aws s3': 7, 'php': 7,
    }

    @staticmethod
    def priority_for_tech(tech_str):
        if not tech_str:
            return 5
        t = tech_str.lower()
        max_p = 5
        for tech, prio in Importer.TECH_PRIORITY.items():
            if tech in t:
                max_p = max(max_p, prio)
        return min(max_p, 10)

    @staticmethod
    def from_recon_json(hunt_id, json_path):
        if not os.path.exists(json_path):
            return 0
        with open(json_path) as f:
            data = json.load(f)
        added = 0
        for sub in data.get('alive_subdomains', []):
            sub_name = sub.get('sub', '')
            if not sub_name:
                continue
            techs = sub.get('tech', [])
            tech_str = ','.join(techs)
            prio = Importer.priority_for_tech(tech_str)
            title = (sub.get('title') or '').lower()
            if any(x in title for x in ['test', 'staging', 'dev', 'admin', 'panel', 'login']):
                prio = min(prio + 2, 10)
            added += Asset.add(hunt_id, 'subdomain', sub_name,
                             source='recon_tool', tech=tech_str,
                             status_code=sub.get('status'),
                             priority=prio)
        return added

    @staticmethod
    def from_gobuster(hunt_id, txt_path, base_url):
        if not os.path.exists(txt_path):
            return 0
        added = 0
        prio_map = {
            '/admin': 9, '/login': 8, '/panel': 8, '/dashboard': 8,
            '/backup': 9, '/old': 7, '/test': 8, '/dev': 8,
            '/.git': 10, '/.env': 10, '/.svn': 9,
            '/api': 6, '/v1': 6, '/v2': 6,
            '/config': 7, '/db': 8, '/sql': 9,
            '/phpmyadmin': 10, '/adminer': 9,
            '/upload': 6, '/uploads': 5,
        }
        with open(txt_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                m = re.search(r'Path:\s*(\S+)', line)
                path = m.group(1) if m else line
                prio = 5
                for pattern, p in prio_map.items():
                    if pattern in path.lower():
                        prio = p
                        break
                value = base_url.rstrip('/') + path
                added += Asset.add(hunt_id, 'endpoint', value,
                                 source='gobuster', priority=prio)
        return added

    @staticmethod
    def from_txt(hunt_id, txt_path, atype='url', priority=5):
        if not os.path.exists(txt_path):
            return 0
        with open(txt_path) as f:
            values = f.readlines()
        return Asset.bulk_add(hunt_id, atype, values, source='txt-import',
                            priority=priority)


# ═══════════════════════════════════════════
#  PRIORIZAÇÃO INTELIGENTE
# ═══════════════════════════════════════════

class Prioritizer:
    VALUE_SIGNALS = {
        'admin': 9, 'login': 8, 'auth': 7, 'sso': 7,
        'api': 6, 'v1': 6, 'v2': 6, 'graphql': 7,
        'backup': 10, 'dump': 10, 'bak': 9, 'old': 6,
        'test': 8, 'staging': 9, 'dev': 8, 'uat': 8,
        'config': 8, 'env': 10, 'conf': 7,
        'git': 9, 'svn': 9, 'panel': 8, 'cpanel': 9,
        'phpmyadmin': 10, 'adminer': 9,
        'upload': 6, 'docs': 4, 'help': 3, 'blog': 4,
        'mail': 6, 'smtp': 7, 'webmail': 7,
        'jenkins': 9, 'grafana': 8, 'kibana': 8,
        'internal': 8, 'intranet': 8, 'portal': 6,
    }
    LOW_SIGNALS = {
        'cdn': 1, 'static': 1, 'assets': 1, 'img': 2,
        'images': 2, 'media': 2, 'www': 3,
    }

    @staticmethod
    def score(asset):
        score = 30
        value = asset['value'].lower()
        tech = (asset.get('tech') or '').lower()
        for pattern, pts in Prioritizer.VALUE_SIGNALS.items():
            if pattern in value:
                score += pts * 3
        for pattern, pts in Prioritizer.LOW_SIGNALS.items():
            if pattern in value:
                score -= pts * 3
        score += Importer.priority_for_tech(tech) * 2
        sc = asset.get('status_code')
        if sc == 200:
            score += 5
        elif sc and 300 <= sc < 400:
            score += 3
        elif sc == 403:
            score += 6
        elif sc == 404:
            score -= 8
        return max(0, min(score, 100))

    @staticmethod
    def requeue_all(hunt_id):
        db = get_db()
        rows = db.execute(
            "SELECT * FROM assets WHERE hunt_id=? AND tested=0",
            (hunt_id,)).fetchall()
        updated = 0
        for r in rows:
            asset = dict(r)
            score = Prioritizer.score(asset)
            prio = max(1, min(10, round(score / 10)))
            db.execute("UPDATE assets SET priority=? WHERE id=?",
                      (prio, asset['id']))
            updated += 1
        db.commit()
        db.close()
        return updated


# ═══════════════════════════════════════════
#  REPORT GENERATOR
# ═══════════════════════════════════════════

class ReportGenerator:
    SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

    @staticmethod
    def generate_markdown(hunt, findings):
        now = datetime.now().strftime('%d/%m/%Y %H:%M')
        md = "# Vulnerability Report - " + hunt['name'] + "\n\n"
        md += "**Generated:** " + now + "\n"
        md += "**Program:** " + hunt.get('platform', 'manual') + "\n"
        md += "**Scope:** " + hunt.get('scope', 'N/A') + "\n\n"
        md += "## Summary\n\n| Severity | Count |\n|---|---|\n"
        by_sev = {}
        for f in findings:
            by_sev.setdefault(f['severity'], []).append(f)
        for sev in ReportGenerator.SEVERITY_ORDER:
            n = len(by_sev.get(sev, []))
            md += "| " + sev.upper() + " | " + str(n) + " |\n"
        md += "\n## Findings\n"
        for sev in ReportGenerator.SEVERITY_ORDER:
            for f in by_sev.get(sev, []):
                md += "\n### [" + f['severity'].upper() + "] " + f['title'] + "\n\n"
                md += "**Type:** " + f['type'] + "\n"
                md += "**Status:** " + f['status'] + "\n\n"
                md += "**Description:**\n" + (f['description'] or 'n/a') + "\n\n"
                md += "**Evidence:**\n" + (f['evidence'] or 'n/a') + "\n\n---\n"
        md += "\n*Report generated by HUNT v" + VERSION + " - shinei*\n"
        return md

    @staticmethod
    def generate_html(hunt, findings):
        sev_colors = {'critical': '#ff0000', 'high': '#ff6600',
                      'medium': '#ffcc00', 'low': '#88cc00', 'info': '#888888'}
        rows = ""
        for f in sorted(findings, key=lambda x:
                        ReportGenerator.SEVERITY_ORDER.index(x['severity'])
                        if x['severity'] in ReportGenerator.SEVERITY_ORDER else 99):
            color = sev_colors.get(f['severity'], '#888')
            rows += ("<tr><td><b style='color:" + color + "'>"
                     + f['severity'].upper() + "</b></td><td>"
                     + html_mod.escape(f['title']) + "</td><td>"
                     + f['type'] + "</td><td>" + f['status'] + "</td><td>"
                     + str(f['bounty'] or '-') + "</td><td>"
                     + f['found_at'][:10] + "</td></tr>")
        total_bounty = Finding.total_bounty(hunt['id'])
        h = ("<!DOCTYPE html><html><head><meta charset='UTF-8'>"
             "<title>HUNT Report</title><style>"
             "*{margin:0;padding:0;box-sizing:border-box}"
             "body{background:#0a0e14;color:#d8d8d8;font-family:monospace;padding:20px}"
             ".container{max-width:1100px;margin:0 auto}"
             "header{border:2px solid #00ff88;padding:25px;margin-bottom:25px}"
             "h1{color:#00ff88}.meta{color:#888;font-size:.9em}"
             "table{width:100%;border-collapse:collapse;margin:20px 0}"
             "th{background:#14181f;color:#00ff88;padding:10px;text-align:left}"
             "td{padding:8px;border-bottom:1px solid #222;font-size:.9em}"
             ".bounty{color:#00ff88;font-size:1.4em;margin:15px 0}"
             "</style></head><body><div class='container'>"
             "<header><h1>HUNT - Bug Bounty Report</h1>"
             "<div class='meta'>Hunt: " + html_mod.escape(hunt['name']) + "</div>"
             "<div class='meta'>Generated: " + datetime.now().strftime('%d/%m/%Y %H:%M') + "</div>"
             "</header>"
             "<div class='bounty'>Total bounty: $" + str(total_bounty) + "</div>"
             "<table><tr><th>Severity</th><th>Title</th><th>Type</th>"
             "<th>Status</th><th>Bounty</th><th>Found</th></tr>"
             + rows + "</table></div></body></html>")
        return h

    @staticmethod
    def save_and_open(hunt, findings, fmt='html'):
        outdir = BASE / "reports" / hunt['name'].replace(' ', '_')
        outdir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        if fmt in ('md', 'both'):
            fp = outdir / f"report_{ts}.md"
            fp.write_text(ReportGenerator.generate_markdown(hunt, findings),
                        encoding='utf-8')
            print(f"{GREEN}[OK] Markdown: {fp}{NC}")
        if fmt in ('html', 'both'):
            fp = outdir / f"report_{ts}.html"
            fp.write_text(ReportGenerator.generate_html(hunt, findings),
                        encoding='utf-8')
            print(f"{GREEN}[OK] HTML: {fp}{NC}")
            os.system(f"cp {fp} ~/storage/shared/Download/ 2>/dev/null")
            os.system(f"termux-open ~/storage/shared/Download/{fp.name} 2>/dev/null")


# ═══════════════════════════════════════════
#  STATS
# ═══════════════════════════════════════════

class Stats:
    @staticmethod
    def global_stats():
        db = get_db()
        hunts = db.execute("SELECT COUNT(*) FROM hunts").fetchone()[0]
        assets = db.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        tested = db.execute("SELECT COUNT(*) FROM assets WHERE tested=1").fetchone()[0]
        findings = db.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        reported = db.execute(
            "SELECT COUNT(*) FROM findings WHERE status IN ('reported','triaged','accepted','paid')"
        ).fetchone()[0]
        bounty = db.execute(
            "SELECT SUM(bounty) FROM findings WHERE bounty>0").fetchone()[0] or 0
        by_sev = db.execute(
            "SELECT severity, COUNT(*) as n FROM findings GROUP BY severity"
        ).fetchall()
        by_type = db.execute(
            "SELECT type, COUNT(*) as n FROM findings GROUP BY type ORDER BY n DESC"
        ).fetchall()
        db.close()
        return {'hunts': hunts, 'assets': assets, 'tested': tested,
                'findings': findings, 'reported': reported, 'bounty': bounty,
                'by_severity': [dict(r) for r in by_sev],
                'by_type': [dict(r) for r in by_type]}


# ═══════════════════════════════════════════
#  PAINEL INTERATIVO
# ═══════════════════════════════════════════

def banner():
    print(f"{MAGENTA}")
    print("  ╔══════════════════════════════════════╗")
    print("  ║   🎯 HUNT — Bug Bounty Center        ║")
    print("  ║   v" + VERSION + " · shinei                  ║")
    print("  ╚══════════════════════════════════════╝")
    print(f"{NC}")


def pause():
    input(f"\n{GRAY}[Enter pra voltar]{NC}")


def pick_hunt():
    """Lista hunts e deixa escolher um"""
    hunts = Hunt.list()
    if not hunts:
        print(f"{RED}[!] Nenhum hunt. Cria com: hunt new{NC}")
        return None
    print(f"\n{BOLD}Hunts:{NC}")
    for h in hunts:
        status_color = GREEN if h['status'] == 'active' else GRAY
        print(f"  [{h['id']}] {h['name']} {status_color}({h['status']}){NC}")
    c = input(f"\n{YELLOW}[?] Hunt (número ou nome): {NC}").strip()
    if not c:
        return None
    hunt = Hunt.get(c)
    if not hunt:
        print(f"{RED}[!] Hunt não encontrado{NC}")
        return None
    return hunt


# ─── Ações do menu de hunt ───

def hunt_menu():
    hunt = pick_hunt()
    if not hunt:
        return
    hid = hunt['id']
    while True:
        print(f"\n{MAGENTA}═══ HUNT: {hunt['name']} ({hunt['status']}) ═══{NC}")
        print(f"{YELLOW}[1]{NC} Ver superfície (fila de testes)")
        print(f"{YELLOW}[2]{NC} Importar assets (recon/gobuster/txt)")
        print(f"{YELLOW}[3]${NC} Marcar asset como testado")
        print(f"{YELLOW}[4]{NC} Registrar finding")
        print(f"{YELLOW}[5]{NC} Ver findings")
        print(f"{YELLOW}[6]{NC} Re-priorizar fila (inteligente)")
        print(f"{YELLOW}[7]{NC} Ver diário de caça")
        print(f"{YELLOW}[8]{NC} Gerar report")
        print(f"{YELLOW}[9]{NC} Mudar status do hunt")
        print(f"{YELLOW}[0]${NC} ← Voltar")
        c = input(f"{GREEN}Escolha: {NC}").strip()

        if c == '1':
            stats = Asset.stats(hid)
            print(f"\n{BOLD}Superfície: {stats['total']} assets "
                  f"({stats['tested']} testados, {stats['pending']} pendentes){NC}")
            if stats['by_type']:
                print(f"{GRAY}Por tipo:{NC}")
                for t in stats['by_type']:
                    print(f"  {t['type']}: {t['n']}")
            if stats['by_tech']:
                print(f"{GRAY}Techs detectadas:{NC}")
                for t in stats['by_tech'][:10]:
                    print(f"  {t['tech']}: {t['n']}")

            queue = Asset.queue(hid)[:15]
            if queue:
                print(f"\n{BOLD}Top da fila (prioridade):{NC}")
                for a in queue:
                    pc = {1: RED, 5: YELLOW, 8: GREEN}.get(
                        a['priority'] // 3, GRAY)
                    tested = f"{GRAY}[testado]{NC}" if a['tested'] else ""
                    print(f"  {pc}[P{a['priority']:>2}]{NC} {a['type']:10s} "
                          f"{a['value'][:50]} {tested}")
            pause()

        elif c == '2':
            print(f"\n{YELLOW}Importar de onde?{NC}")
            print(f"[1] recon_tool.py JSON")
            print(f"[2] Gobuster output (precisa base URL)")
            print(f"[3] TXT simples (1 valor/linha)")
            ic = input("Escolha: ").strip()
            path = input(f"{YELLOW}Caminho do arquivo: {NC}").strip()
            path = os.path.expanduser(path)
            if ic == '1':
                n = Importer.from_recon_json(hid, path)
                print(f"{GREEN}[+] {n} subdomínios importados{NC}")
            elif ic == '2':
                base = input(f"{YELLOW}Base URL (ex: https://alvo.com): {NC}").strip()
                n = Importer.from_gobuster(hid, path, base)
                print(f"{GREEN}[+] {n} endpoints importados{NC}")
            elif ic == '3':
                atype = input(f"{YELLOW}Tipo [url]: {NC}").strip() or 'url'
                n = Importer.from_txt(hid, path, atype)
                print(f"{GREEN}[+] {n} assets importados{NC}")
            Log.add(hid, "import", f"tipo {ic}, arquivo {path}")
            Prioritizer.requeue_all(hid)
            print(f"{GREEN}[+] Fila re-priorizada automaticamente{NC}")
            pause()

        elif c == '3':
            aid = input(f"{YELLOW}[?] Asset ID: {NC}").strip()
            try:
                Asset.mark_tested(int(aid))
                Log.add(hid, "asset testado", f"id={aid}")
                print(f"{GREEN}[✓] Marcado como testado{NC}")
            except ValueError:
                print(f"{RED}[!] ID inválido{NC}")
            pause()

        elif c == '4':
            ftype = input(f"{YELLOW}[?] Tipo (sqli/xss/ssrf/idor/info...): {NC}").strip()
            title = input(f"{YELLOW}[?] Título: {NC}").strip()
            sev = input(f"{YELLOW}[?] Severidade [medium]: {NC}").strip() or 'medium'
            desc = input(f"{YELLOW}[?] Descrição (opcional): {NC}").strip()
            evid = input(f"{YELLOW}[?] Evidência/payload (opcional): {NC}").strip()
            fid = Finding.add(hid, ftype, title, sev, None, desc, evid)
            Log.add(hid, "finding registrado", f"[{sev}] {title}")
            print(f"{GREEN}[✓] Finding #{fid} registrado{NC}")
            pause()

        elif c == '5':
            findings = Finding.list(hid)
            if not findings:
                print(f"{GRAY}Nenhum finding ainda{NC}")
            else:
                sev_colors = {'critical': RED, 'high': YELLOW,
                            'medium': CYAN, 'low': GRAY, 'info': GRAY}
                for f in findings:
                    color = sev_colors.get(f['severity'], GRAY)
                    print(f"  [{f['id']}] {color}[{f['severity'].upper()}]{NC} "
                          f"{f['title']} {GRAY}({f['status']}){NC}")
                total = Finding.total_bounty(hid)
                if total > 0:
                    print(f"\n  {GREEN}💰 Total bounty: ${total:.2f}{NC}")
            pause()

        elif c == '6':
            n = Prioritizer.requeue_all(hid)
            print(f"{GREEN}[✓] {n} assets re-priorizados{NC}")
            pause()

        elif c == '7':
            entries = Log.tail(hid, 30)
            print(f"\n{BOLD}Diário de caça:{NC}")
            for e in entries:
                print(f"  {GRAY}{e['created_at'][:16]}{NC} {e['action']} "
                      f"{GRAY}{e['detail'][:50]}{NC}")
            pause()

        elif c == '8':
            findings = Finding.list(hid)
            fmt = input(f"{YELLOW}[?] Formato (html/md/both) [html]: {NC}").strip() or 'html'
            ReportGenerator.save_and_open(hunt, findings, fmt)
            pause()

        elif c == '9':
            print(f"{YELLOW}Status: active / paused / done / dropped{NC}")
            new = input("[?] Novo status: ").strip()
            if new in ('active', 'paused', 'done', 'dropped'):
                Hunt.update_status(hid, new)
                hunt['status'] = new
                Log.add(hid, "status mudado", new)
                print(f"{GREEN}[✓] Status: {new}{NC}")
            pause()

        elif c == '0':
            return


def cmd_new(args):
    init_db()
    banner()
    hid = Hunt.create(args.name, args.platform or 'manual',
                     args.scope or '', args.oos or '',
                     args.auth or '', args.bmin or 0, args.bmax or 0)
    if hid:
        print(f"{GREEN}[✓] Hunt criado: {args.name} (id {hid}){NC}")
        print(f"\n{CYAN}Adiciona a superfície com:{NC}")
        print(f"  hunt add-assets {hid}")
    else:
        print(f"{RED}[!] Hunt com esse nome já existe{NC}")


def cmd_add_assets(args):
    init_db()
    hunt = Hunt.get(args.hunt)
    if not hunt:
        print(f"{RED}[!] Hunt não encontrado{NC}")
        sys.exit(1)
    hid = hunt['id']
    n = 0
    if args.recon:
        n += Importer.from_recon_json(hid, args.recon)
    if args.gobuster:
        n += Importer.from_gobuster(hid, args.gobuster, args.base or '')
    if args.txt:
        atype = args.type or 'url'
        n += Importer.from_txt(hid, args.txt, atype)
    print(f"{GREEN}[+] {n} assets importados{NC}")
    Prioritizer.requeue_all(hid)
    print(f"{GREEN}[+] Fila re-priorizada{NC}")
    Log.add(hid, "import", f"{n} assets")


def cmd_queue(args):
    init_db()
    hunt = Hunt.get(args.hunt)
    if not hunt:
        print(f"{RED}[!] Hunt não encontrado{NC}")
        sys.exit(1)
    queue = Asset.queue(hunt['id'])
    print(f"\n{BOLD}Fila de testes — {len(queue)} pendentes{NC}\n")
    for a in queue[:30]:
        print(f"  [P{a['priority']:>2}] {a['type']:10s} {a['value'][:60]}")
    if len(queue) > 30:
        print(f"  {GRAY}... +{len(queue)-30}{NC}")


def cmd_stats(args):
    init_db()
    banner()
    st = Stats.global_stats()
    print(f"\n{BOLD}═══ ESTATÍSTICAS GLOBAIS ═══{NC}\n")
    print(f"  Hunts: {st['hunts']}")
    print(f"  Assets na superfície: {st['assets']} ({st['tested']} testados)")
    print(f"  Findings: {st['findings']} ({st['reported']} reportados)")
    if st['by_severity']:
        print(f"\n  {CYAN}Por severidade:{NC}")
        for s in st['by_severity']:
            print(f"    {s['severity']}: {s['n']}")
    if st['by_type']:
        print(f"\n  {CYAN}Por tipo:{NC}")
        for s in st['by_type']:
            print(f"    {s['type']}: {s['n']}")
    print(f"\n  {GREEN}💰 Bounty total: ${st['bounty']:.2f}{NC}")


# ═══════════════════════════════════════════
#  MAIN / CLI
# ═══════════════════════════════════════════

def main():
    init_db()
    import argparse
    ap = argparse.ArgumentParser(
        prog='hunt',
        description=f'HUNT v{VERSION} — Bug Bounty Command Center',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Exemplos:
  hunt new -n "programa-x" -p hackerone --scope "*.alvo.com"
  hunt add-assets 1 --recon recon_alvo.json
  hunt queue 1
  hunt stats
  hunt                (abre painel interativo)

Uso ético: gerencia caças AUTORIZADAS apenas.
        ''')
    sub = ap.add_subparsers(dest='cmd')

    p = sub.add_parser('new', help='Cria novo hunt')
    p.add_argument('-n', '--name', required=True)
    p.add_argument('-p', '--platform', help='hackerone/bugcrowd/manual')
    p.add_argument('--scope', help='escopo permitido')
    p.add_argument('--oos', help='fora de escopo')
    p.add_argument('--auth', help='URL da policy/contrato')
    p.add_argument('--bmin', type=float, help='bounty mínimo')
    p.add_argument('--bmax', type=float, help='bounty máximo')
    p.set_defaults(func=cmd_new)

    p = sub.add_parser('add-assets', help='Importa superfície')
    p.add_argument('hunt', help='id ou nome do hunt')
    p.add_argument('--recon', help='JSON do recon_tool')
    p.add_argument('--gobuster', help='output do gobuster')
    p.add_argument('--base', help='base URL pro gobuster')
    p.add_argument('--txt', help='txt simples')
    p.add_argument('--type', help='tipo pro txt [url]')
    p.set_defaults(func=cmd_add_assets)

    p = sub.add_parser('queue', help='Fila de testes de um hunt')
    p.add_argument('hunt')
    p.set_defaults(func=cmd_queue)

    p = sub.add_parser('stats', help='Estatísticas globais')
    p.set_defaults(func=cmd_stats)

    args = ap.parse_args()
    if not args.cmd:
        # Sem comando = painel interativo (menu de hunts)
        banner()
        hunt_menu()
        return
    args.func(args)


if __name__ == '__main__':
    main()
