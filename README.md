# 🎯 HUNT

### Bug Bounty Command Center

**Gestão completa de caça a vulnerabilidades — direto do seu Android**

Python 3.x | Termux | Authorized Use Only

*Recon imports · Smart prioritization · Findings tracking · Professional reports*

---

## 💡 Por que o HUNT existe

Bug bounty não falha por falta de skill — falha por **falta de organização**:

- Subdomínios descobertos e esquecidos em arquivos soltos
- Endpoints testados duas vezes (ou piores: nunca)
- Findings anotados no bloco de notas que somem
- Reports montados às pressas, perdendo valor

O HUNT resolve isso: um command center que transforma caça caótica em operação organizada.

---

## ⚡ Features

### 🗂 Hunt Management
Cada programa de bounty é um "hunt" — com escopo documentado, outside-of-scope explícito, link da policy, bounty range. A autorização é parte do dado, não um lembrete mental.

### 🌐 Superfície Unificada
Importa direto de:
- **recon_tool.py** (JSON — subdomínios + tech detectada)
- **gobuster** (endpoints + status codes)
- **nmap, txt simples** — qualquer fonte, 1 valor por linha

Tudo num único banco SQLite, deduplicado automaticamente.

### 🧠 Priorização Inteligente
Score 0-100 por asset baseado em múltiplos sinais:

| Sinal | Efeito |
|-------|--------|
| admin, backup, .env no nome | +30 |
| cdn, static, img no nome | -9 |
| WordPress/Jenkins/Tomcat detectado | +8 a 20 |
| Cloudflare/WAF | mais difícil |
| HTTP 403 | +6 (403 esconde coisa!) |
| HTTP 404 | -8 |

O sistema decide sozinho o que testar primeiro.

Exemplo real — fila após import:

    [P 7] admin.alvolab.com     <- testar JÁ
    [P 6] test.alvolab.com
    [P 6] api.alvolab.com
    [P 4] cdn.alvolab.com       <- ignora por ora

### 🐛 Findings Tracking
Cada vulnerabilidade registrada com severidade, evidência, payload usado, e ciclo de vida completo:

    draft -> reported -> triaged -> accepted -> paid

### 📄 Report Generator
Report em Markdown (formato HackerOne) e HTML dark theme — severidade colorida, bounty total, metodologia. Pronto pra submeter.

### 📔 Diário de Caça
Log automático de tudo: imports, testes, status changes. Nunca mais "eu já testei isso?".

---

## 🚀 Instalação

    pkg install python -y
    git clone https://github.com/cauelucas172-maker/hunt.git
    cd hunt

Sem dependências externas — só Python stdlib + SQLite nativo.

---

## 📖 Uso

### Criar um hunt

    hunt new -n "programa-x" -p hackerone --scope "*.alvo.com" --bmin 100 --bmax 5000

### Alimentar a superfície

    # Do recon_tool.py
    hunt add-assets 1 --recon recon_alvo.json

    # Do gobuster
    hunt add-assets 1 --gobuster gobuster.txt --base "https://alvo.com"

    # Ou txt simples
    hunt add-assets 1 --txt lista.txt

### Trabalhar

    hunt          # painel interativo completo
    hunt queue 1  # fila de testes priorizada
    hunt stats    # estatísticas globais

---

## 🏗 Arquitetura

    hunt.py (~950 linhas, zero dependências)
    ├── SQLite (hunt.db)
    │   ├── hunts      -> programas/alvos
    │   ├── assets     -> superfície
    │   ├── findings   -> vulnerabilidades + lifecycle
    │   └── hunt_log   -> diário automático
    ├── Importer       -> recon JSON, gobuster, txt
    ├── Prioritizer    -> score 0-100 multi-signal
    ├── ReportGenerator-> Markdown + HTML
    └── Stats          -> KPIs globais

---

## ⚠️ Uso Ético

O HUNT gerencia caças AUTORIZADAS apenas:

- Bug bounty com escopo documentado
- Pentest com contrato assinado
- Seus próprios sistemas
- NUNCA terceiros sem permissão

Acesso não autorizado é crime — Art. 154-A CP (Brasil), CFAA (EUA), e equivalentes no mundo todo. O sistema registra o contexto de autorização de cada hunt por design: a organização começa na ética.

---

<div align="center">

**Built on a Galaxy A15 — Termux only — zero PC**

por shinei

</div>

