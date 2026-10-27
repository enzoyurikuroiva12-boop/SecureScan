# Regras locais do SecureScan

As regras abaixo são heurísticas estáticas. O nível indica prioridade de revisão, não prova de explorabilidade. Resultados podem ser falsos positivos ou exigir configuração/contexto que o scanner não conhece.

| Regra | Detecção | Gravidade | Limitação |
| --- | --- | --- | --- |
| `SEC-SECRET-001` | Atribuições com nomes como `api_key`, `secret`, `private_key`, `password`, `token` ou `credential`; formatos reconhecíveis de chaves AWS, GitHub, Google, Slack, npm, Stripe e JWT; credenciais em URLs; marcador de chave privada PEM | Alta | Padrões não identificam todos os provedores e podem sinalizar valores de exemplo. O conteúdo não é validado contra o serviço emissor. |
| `SEC-SECRET-ENV` | Arquivo chamado `.env` em qualquer diretório extraído | Média | A presença do arquivo não prova que há credenciais nem que ele será publicado. |
| `SEC-DOCKER-001` | Instrução `FROM` sem tag ou digest, excluindo `scratch` e aliases de estágios anteriores | Baixa | Não identifica se a imagem é privada, imutável por política externa ou qual tag atende à organização. |
| `SEC-DOCKER-002` | Dockerfile sem instrução `USER` | Informativa | A imagem base ou o runtime podem definir o usuário por outros meios. |
| `SEC-DOCKER-ROOT` | Instrução `USER root` ou `USER 0` | Baixa | A necessidade de privilégios depende do processo executado. |
| `SEC-CONFIG-DEBUG` | `DEBUG=True` em `settings.py`, `config.py` ou `configuration.py` | Média | Não resolve qual arquivo/valor é usado em produção. |
| `SEC-GITIGNORE-ENV` | Quando `.env` existe, falta uma regra simples `.env` ou `.env*` no `.gitignore` raiz | Baixa | Não interpreta todas as regras Git ou `.git/info/exclude`. |

Os padrões de atribuição exigem valor com pelo menos quatro caracteres. Placeholders literais comuns são ignorados. Valores e trechos de Bandit são mascarados antes de serem persistidos. Não há consulta de segredos a serviços externos nem inspeção de histórico Git.

## Dependências

O SecureScan gera um arquivo temporário apenas com pares `pacote==versão` extraídos de `requirements*.txt` ou `pylock*.toml`. Ele chama pip-audit com `--vulnerability-service=osv --no-deps --disable-pip`; assim, o instalador e a resolução de dependências ficam desativados. Entradas de URLs, VCS, intervalos, opções e fontes personalizadas são omitidas. Dependências transitivas ausentes dos pins não entram na consulta.

Quando OSV fornece uma categoria textual, ela é preservada e mapeada. Uma pontuação CVSS numérica usa os limites 0.1–3.9 baixa, 4.0–6.9 média, 7.0–8.9 alta e 9.0–10 crítica. Um vetor CVSS sem pontuação não é convertido; nesses casos a categoria fica `Informativa` e o campo `original_severity` retém o valor recebido.
