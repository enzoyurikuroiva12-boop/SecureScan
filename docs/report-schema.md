# SecureScan JSON report schema 1.0.0

O endpoint `GET /api/v1/scans/{id}/report` retorna um objeto com:

- `schema_version`: versão semântica do contrato do relatório.
- `generated_at`: instante da exportação em ISO 8601.
- `analysis`: id, projeto, estado e timestamps da execução.
- `summary`: arquivos examinados, quantidade e contagem por gravidade.
- `tools`: ferramenta, versão observada, estado e observação de execução.
- `findings`: achados normalizados com regra, origem, severidade, arquivo/linha, recomendação e referências. `files` agrupa manifests de origem de um aviso de dependência duplicado. `source` e `source_consulted_at` identificam a fonte e o instante de consulta/execução.
- `limitations`: verificações não feitas e limites conhecidos, incluindo a ausência de resolução de dependências transitivas.
- `configuration`: seleções de módulos da análise.
- `tool_statuses`: mapa auxiliar de ferramenta para estado.

Gravidades normalizadas: `Crítica`, `Alta`, `Média`, `Baixa` e `Informativa`. `original_severity` preserva o valor da ferramenta quando disponível. Bandit usa os rótulos de severidade próprios; valores categóricos de OSV são mapeados para a categoria correspondente e pontuações numéricas usam os limites CVSS 0.1–3.9 baixa, 4.0–6.9 média, 7.0–8.9 alta e 9.0–10 crítica. Vetores CVSS sem pontuação não são interpretados e permanecem `Informativa`. Segredos detectados nunca aparecem completos em `evidence`.
