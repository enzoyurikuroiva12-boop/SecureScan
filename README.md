# SecureScan

SecureScan é um MVP local para revisão defensiva de projetos que você tem autorização para analisar. Ele examina arquivos ZIP sem executar scripts enviados ou instalar dependências do projeto.

## Recursos desta versão

- Upload ZIP com limites de tamanho, quantidade de arquivos, tamanho descompactado e razão de compressão.
- Extração manual com rejeição de caminhos absolutos, traversal e links simbólicos; diretórios de build e dependências são ignorados.
- Worker em segundo plano com limite de duas análises concorrentes e timeout por ferramenta externa.
- Regras locais para padrões de credenciais, arquivos `.env`, Dockerfile, configuração de debug e `.gitignore`. Valores detectados são mascarados antes da persistência.
- `pip-audit` para pins exatos em `requirements*.txt` e lockfiles PEP 751 `pylock*.toml`, com consulta ao OSV, quando instalado. A execução usa `--no-deps --disable-pip`: não resolve transitivas nem chama o instalador. Linhas com URLs, opções, intervalos ou fontes personalizadas são ignoradas por segurança e informadas.
- Bandit para código Python, quando instalado.
- Histórico em SQLite, API versionada, dashboard, filtros de resultados e relatório JSON `schema_version: 1.0.0`.
- Migrations Alembic e suíte de testes sintéticos.
- Catálogo das regras locais e das limitações de detecção em [`docs/detection-rules.md`](docs/detection-rules.md).

## Requisitos

- Python 3.11 ou superior.
- Node.js 20.19+ ou 22.12+ e npm (requisito do Vite 8).
- `pip-audit` e `bandit` são opcionais. Instale-os no ambiente local do serviço para habilitar as verificações externas:

```powershell
py -m pip install "pip-audit>=2.10.1,<3" "bandit>=1.8,<2"
```

`pip-audit` consulta dados públicos de vulnerabilidades. O SecureScan não envia arquivos de projeto; para dependências, apenas nomes e versões pinadas são fornecidos à ferramenta. A ferramenta é chamada com resolução desativada; dependências transitivas ausentes da lista pinada não são auditadas. Linhas de requisitos com fontes, opções, VCS ou intervalos são omitidas.

## Instalação e execução no Windows

Com Python 3.11+, Node.js 20.19+ (ou 22.12+) e npm instalados, execute `baixar.bat` na raiz do projeto. O script cria `.venv`, instala as dependências Python e da interface, instala `pip-audit` e Bandit, cria `.env` a partir de `.env.example` sem substituir uma configuração existente e prepara o banco SQLite.

Depois execute `iniciar.bat`. Ele abre a API e a interface em janelas separadas, vinculadas somente a `127.0.0.1`, e abre a interface no navegador. Encerre cada serviço com Ctrl+C na janela correspondente.

## Instalação e execução local

Na raiz do projeto, crie e configure o ambiente Python:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
alembic upgrade head
uvicorn securescan.main:app --app-dir backend --host 127.0.0.1 --port 8000 --env-file .env
```

Em outro terminal:

```powershell
cd frontend
npm install
npm run dev
```

Abra <http://127.0.0.1:5173>. A documentação OpenAPI fica em <http://127.0.0.1:8000/docs> e a verificação de saúde em <http://127.0.0.1:8000/api/v1/health>.

O banco e os dados temporários ficam em `data/`. Para PostgreSQL, configure `SECURESCAN_DATABASE_URL` com uma URL `postgresql+psycopg://usuario:senha@host:5432/securescan` e ajuste o diretório de dados. Execute a API com um único worker Uvicorn: a fila de análises deste MVP é em memória e não coordena múltiplos processos. O MVP é de usuário único, sem autenticação; mantenha a API em loopback e não a exponha em rede compartilhada.

## API principal

- `POST /api/v1/scans` — multipart com `file`, `project_name` e flags `check_dependencies`, `check_secrets`, `check_static`, `check_configuration`.
- `GET /api/v1/scans` — histórico paginado.
- `GET /api/v1/scans/{id}` — estado e resultados.
- `GET /api/v1/scans/{id}/findings` — filtros `severity`, `category`, `file` e `tool`.
- `POST /api/v1/scans/{id}/cancel` — solicita cancelamento; um processo externo em execução é encerrado durante a próxima verificação do worker.
- `GET /api/v1/scans/{id}/report` — relatório JSON após o estado terminal.

Estados: `queued`, `analyzing`, `completed`, `completed_with_warnings`, `failed` e `cancelled`. Ferramentas ausentes, timeouts e verificações ignoradas não são tratados como análise limpa.

## Testes

Testes de arquivo e regras locais, sem serviços externos:

```powershell
python -m unittest discover -s tests -p test_core_unittest.py -v
```

Suíte completa de API e persistência:

```powershell
python -m pytest
```

Os testes usam projetos ZIP sintéticos e um banco isolado em `tests/.test-data`.

## Limitações conhecidas

- Não há autenticação, autorização multiusuário nem isolamento entre usuários; o MVP deve permanecer local.
- O worker usa threads e subprocessos com timeout. Não há sandbox OS-level, limites rígidos de CPU/memória nem isolamento por contêiner. Para implantação compartilhada, mova workers para contêineres efêmeros com privilégios mínimos, rede controlada, limites de recursos e fila externa.
- Não há persistência de ZIP após o processamento; histórico guarda metadados e achados, não o conteúdo-fonte.
- Dependências: `requirements*.txt` com pins exatos e lockfiles PEP 751 `pylock*.toml`; lockfiles Poetry/Pipenv e manifests de Node não fazem parte desta fase.
- Segredos: regras locais limitadas, com possibilidade de falsos positivos; histórico Git só é extraído se estiver no ZIP e não é examinado.
- Bandit e pip-audit dependem de instalação local. A ausência ou falha é reportada e pode levar a `completed_with_warnings`.
- PDF, comparação histórica, agente local, autenticação e processamento em fila dedicado são próximos passos, não recursos implementados neste MVP.
- Um resultado sem achados não prova que o projeto está livre de vulnerabilidades. Os achados estáticos precisam de validação contextual.

Use apenas projetos que você está autorizado a examinar. SecureScan não certifica a segurança de software.
