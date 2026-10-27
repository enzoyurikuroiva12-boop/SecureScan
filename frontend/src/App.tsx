import { useEffect, useMemo, useRef, useState, type ChangeEvent, type DragEvent, type FormEvent, type ReactNode } from 'react'
import { Link, NavLink, Outlet, Route, Routes, useNavigate, useParams } from 'react-router-dom'
import {
  Activity, ArrowDownToLine, ArrowRight, ArrowUpRight, BadgeCheck, Bug, Check, ChevronDown,
  CircleHelp, Clock3, Code2, FileArchive, FileCode2, FileSearch, Fingerprint, FolderKanban,
  HardDriveUpload, History, Layers3, LockKeyhole, Menu, OctagonAlert, PackageCheck,
  Plus, ScanLine, Search, Shield, ShieldAlert, ShieldCheck, ShieldHalf, Sparkles, X,
} from 'lucide-react'
import { API, errorMessage, getScan, getScans, type Finding, type Scan, type ToolResult } from './api'

const severityNames = ['Crítica', 'Alta', 'Média', 'Baixa', 'Informativa']
const categoryNames: Record<string, string> = { dependency: 'Dependências', secrets: 'Segredos', static: 'Código', configuration: 'Configuração' }
const statusNames: Record<string, string> = {
  queued: 'Na fila', analyzing: 'Em análise', completed: 'Concluída', completed_with_warnings: 'Concluída com avisos',
  failed: 'Falhou', cancelled: 'Cancelada', cancelling: 'Cancelando',
}
const formatDate = (value?: string | null) => value ? new Date(value).toLocaleString('pt-BR', { dateStyle: 'medium', timeStyle: 'short' }) : '—'
const formatDuration = (value?: number | null) => value == null ? '—' : value < 60 ? `${value.toFixed(1)}s` : `${Math.floor(value / 60)}min ${Math.round(value % 60)}s`

function Brand({ compact = false }: { compact?: boolean }) {
  return <Link className="brand" to="/" aria-label="SecureScan, página inicial"><span className="brand-mark"><ShieldCheck size={20} strokeWidth={2.2} /></span>{!compact && <span>Secure<span>Scan</span></span>}</Link>
}

function Landing() {
  return <div className="landing">
    <header className="landing-header wrap">
      <Brand />
      <nav className="landing-nav" aria-label="Navegação principal"><a href="#como-funciona">Como funciona</a><a href="#recursos">Recursos</a><a href="#faq">FAQ</a></nav>
      <Link className="button button-small button-quiet" to="/dashboard">Abrir painel <ArrowUpRight size={15} /></Link>
    </header>
    <main>
      <section className="hero wrap">
        <div className="hero-copy">
          <div className="eyebrow"><span className="eyebrow-dot" /> SEGURANÇA QUE COMEÇA NO CÓDIGO</div>
          <h1>Encontre riscos.<br /><span>Corrija antes do deploy.</span></h1>
          <p>Uma análise prática de dependências, segredos e padrões de código para ajudar sua equipe a desenvolver com mais confiança.</p>
          <div className="hero-actions"><Link className="button button-primary" to="/scans/new"><ScanLine size={17} /> Iniciar análise <ArrowRight size={16} /></Link><a className="text-link" href="#como-funciona">Conheça o fluxo <ArrowDownToLine size={15} className="rotate-icon" /></a></div>
          <div className="hero-note"><LockKeyhole size={14} /> Seus arquivos são analisados localmente e removidos após a execução.</div>
        </div>
        <div className="hero-visual" aria-label="Ilustração do fluxo de análise do SecureScan">
          <div className="visual-glow" />
          <div className="scan-card">
            <div className="scan-card-top"><span className="scan-icon"><ScanLine size={17} /></span><div><strong>Fluxo de análise</strong><small>Verificações selecionadas pelo usuário</small></div><span className="live-dot" /></div>
            <div className="scan-step"><span className="step-icon blue"><PackageCheck size={17} /></span><div><strong>Dependências</strong><small>pip-audit · quando instalado</small></div><span className="step-state neutral">OSV</span></div>
            <div className="scan-step"><span className="step-icon violet"><Fingerprint size={17} /></span><div><strong>Segredos expostos</strong><small>Regras locais · valores mascarados</small></div><span className="step-state ready"><Check size={14} /></span></div>
            <div className="scan-step"><span className="step-icon green"><Code2 size={17} /></span><div><strong>Análise estática</strong><small>Bandit · quando instalado</small></div><span className="step-state neutral">AST</span></div>
            <div className="scan-step"><span className="step-icon amber"><Layers3 size={17} /></span><div><strong>Configurações</strong><small>Docker · ambiente · Git</small></div><span className="step-state ready"><Check size={14} /></span></div>
            <div className="scan-card-footer"><span><Shield size={14} /> Não executa o projeto enviado</span><span>SecureScan <span className="footer-version">MVP</span></span></div>
          </div>
          <div className="float-chip chip-top"><span className="chip-dot blue-dot" /> Análise isolada</div><div className="float-chip chip-bottom"><ShieldCheck size={15} /> Relatório mascarado</div>
        </div>
      </section>
      <div className="trust-strip"><div className="wrap trust-inner"><span>FEITO PARA DESENVOLVIMENTO SEGURO</span><b><Code2 size={15} /> Python</b><b><PackageCheck size={15} /> pip-audit</b><b><Bug size={15} /> Bandit</b><b><Fingerprint size={15} /> Regras locais</b></div></div>
      <section className="section wrap" id="como-funciona">
        <div className="section-heading"><div className="eyebrow">UM FLUXO DIRETO</div><h2>Da análise à ação, sem ruído.</h2><p>Entenda o que foi verificado, o que precisa de atenção e onde começar a correção.</p></div>
        <div className="feature-grid" id="recursos">
          <Feature icon={<PackageCheck />} number="01" title="Dependências" text="Consulta vulnerabilidades conhecidas em requirements.txt usando pip-audit e a base OSV." tone="blue" />
          <Feature icon={<Fingerprint />} number="02" title="Segredos" text="Detecta padrões de credenciais no código e mascara os valores encontrados nos resultados." tone="violet" />
          <Feature icon={<Code2 />} number="03" title="Código e configuração" text="Bandit e verificações locais destacam padrões que merecem revisão contextual." tone="green" />
          <Feature icon={<History />} number="04" title="Histórico e relatório" text="Consulte execuções anteriores e exporte os resultados em JSON versionado." tone="amber" />
        </div>
      </section>
      <section className="how-section"><div className="wrap how-grid"><div><div className="eyebrow">PRIVACIDADE POR PADRÃO</div><h2>Seu código é tratado como dado, nunca como execução.</h2><p>O ZIP é validado, extraído em área temporária com limites definidos e removido ao fim da análise. Scripts e dependências do projeto não são executados nem instalados.</p><Link to="/scans/new" className="button button-primary">Começar agora <ArrowRight size={16} /></Link></div><div className="how-list"><HowStep n="1" title="Envie um ZIP" text="Projetos autorizados, até 50 MB." /><HowStep n="2" title="Selecione verificações" text="Escolha quais módulos deseja executar." /><HowStep n="3" title="Revise e corrija" text="Filtre os achados e exporte o relatório." /></div></div></section>
      <section className="section wrap faq-section" id="faq"><div className="section-heading"><div className="eyebrow">PERGUNTAS FREQUENTES</div><h2>Antes de começar.</h2></div><div className="faq-grid"><Faq q="O SecureScan executa os arquivos enviados?">Não. O conteúdo é examinado como dado. A ferramenta não executa scripts do projeto nem instala suas dependências.</Faq><Faq q="Os resultados garantem que o projeto está seguro?">Não. Uma análise sem achados não prova ausência de vulnerabilidades. Revise os resultados no contexto e complemente com outras práticas de segurança.</Faq><Faq q="O SecureScan envia meu código para um serviço externo?">Os arquivos permanecem no ambiente local. pip-audit consulta dados públicos de vulnerabilidades usando informações de pacotes, não envia o código-fonte.</Faq><Faq q="Preciso ter ferramentas instaladas?">As regras locais funcionam sem ferramentas adicionais. pip-audit e Bandit são opcionais; quando ausentes, o relatório informa que a verificação não foi realizada.</Faq></div></section>
      <section className="cta-section wrap"><div><div className="eyebrow">PRONTO PARA REVISAR?</div><h2>Faça uma análise do seu projeto.</h2><p>Use apenas arquivos que você tem autorização para examinar.</p></div><Link className="button button-primary" to="/scans/new">Iniciar análise <ArrowRight size={16} /></Link></section>
    </main>
    <footer className="footer"><div className="wrap footer-inner"><Brand /><span>Ferramenta defensiva para desenvolvimento seguro.</span><div><a href="/docs" onClick={(e) => { e.preventDefault(); window.open(`${API.replace('/api/v1', '')}/docs`, '_blank', 'noopener') }}>Documentação da API</a><a href="#privacidade">Privacidade</a><span>© {new Date().getFullYear()} SecureScan</span></div></div><p className="footer-legal wrap" id="privacidade">Use apenas em projetos que você está autorizado a analisar. Arquivos temporários são removidos após o processamento; resultados e histórico ficam no banco local.</p></footer>
  </div>
}

function Feature({ icon, number, title, text, tone }: { icon: ReactNode; number: string; title: string; text: string; tone: string }) {
  return <article className="feature-card"><div className={`feature-icon ${tone}`}>{icon}</div><span className="feature-number">{number}</span><h3>{title}</h3><p>{text}</p></article>
}
function HowStep({ n, title, text }: { n: string; title: string; text: string }) { return <div className="how-step"><span>{n}</span><div><strong>{title}</strong><p>{text}</p></div><ArrowRight size={16} /></div> }
function Faq({ q, children }: { q: string; children: ReactNode }) { return <details className="faq"><summary>{q}<ChevronDown size={17} /></summary><p>{children}</p></details> }

function Workspace() {
  const [mobileNav, setMobileNav] = useState(false)
  return <div className="workspace">
    <aside className={`sidebar ${mobileNav ? 'sidebar-open' : ''}`}>
      <div className="sidebar-brand"><Brand /><button className="icon-button mobile-close" onClick={() => setMobileNav(false)} aria-label="Fechar menu"><X size={18} /></button></div>
      <div className="workspace-label">WORKSPACE</div>
      <nav className="side-nav" aria-label="Navegação do painel">
        <NavLink to="/dashboard" onClick={() => setMobileNav(false)}><Activity size={17} />Visão geral</NavLink>
        <NavLink to="/scans/new" onClick={() => setMobileNav(false)}><Plus size={17} />Nova análise</NavLink>
        <NavLink to="/history" onClick={() => setMobileNav(false)}><History size={17} />Histórico</NavLink>
      </nav>
      <div className="sidebar-bottom"><div className="sidebar-authorized"><ShieldHalf size={17} /><div><strong>Uso autorizado</strong><span>Analise apenas seus projetos</span></div></div><Link to="/" className="sidebar-home"><CircleHelp size={15} /> Sobre o SecureScan</Link></div>
    </aside>
    {mobileNav && <button className="mobile-backdrop" onClick={() => setMobileNav(false)} aria-label="Fechar navegação" />}
    <div className="workspace-main"><header className="topbar"><button className="icon-button menu-toggle" onClick={() => setMobileNav(true)} aria-label="Abrir menu"><Menu size={19} /></button><div className="breadcrumb"><span>Workspace</span><span>/</span><strong>SecureScan</strong></div><div className="topbar-right"><span className="local-badge"><span /> Ambiente local</span><span className="avatar">SS</span></div></header><main className="page-content"><Outlet /></main></div>
  </div>
}

function Dashboard() {
  const [scans, setScans] = useState<Scan[]>([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const reload = () => { setLoading(true); getScans().then((data) => { setScans(data); setError('') }).catch((e: Error) => setError(e.message)).finally(() => setLoading(false)) }
  useEffect(() => { reload() }, [])
  const completed = scans.filter((scan) => ['completed', 'completed_with_warnings'].includes(scan.status))
  const projects = new Set(scans.map((scan) => scan.project_name)).size
  const totalFindings = completed.reduce((sum, scan) => sum + scan.finding_count, 0)
  const severity = severityNames.map((name) => [name, completed.reduce((sum, scan) => sum + (scan.severity_counts[name] || 0), 0)] as const)
  const totalSeverity = severity.reduce((sum, item) => sum + item[1], 0)
  const recent = scans.slice(0, 5)
  return <>
    <div className="page-heading"><div><div className="eyebrow">PAINEL DE SEGURANÇA</div><h1>Visão geral</h1><p>Acompanhe análises e priorize o que merece atenção.</p></div><Link to="/scans/new" className="button button-primary"><Plus size={17} /> Nova análise</Link></div>
    {error && <div className="notice notice-error"><OctagonAlert size={18} /><div><strong>Não foi possível conectar à API.</strong><span>{error} Inicie o servidor seguindo as instruções do README.</span></div><button className="button button-small button-quiet" onClick={reload}>Tentar novamente</button></div>}
    <div className="stats-grid">
      <Stat icon={<ScanLine />} label="Análises realizadas" value={loading ? '—' : String(scans.length)} detail="Inclui análises em andamento" tone="blue" />
      <Stat icon={<FolderKanban />} label="Projetos analisados" value={loading ? '—' : String(projects)} detail="Nomes de projetos distintos" tone="violet" />
      <Stat icon={<ShieldAlert />} label="Achados identificados" value={loading ? '—' : String(totalFindings)} detail="Em análises concluídas" tone="red" />
      <Stat icon={<BadgeCheck />} label="Análises concluídas" value={loading ? '—' : String(completed.length)} detail="Com ou sem avisos de ferramenta" tone="green" />
    </div>
    <div className="dashboard-grid">
      <section className="panel severity-panel"><div className="panel-heading"><div><h2>Achados por gravidade</h2><p>Dados das análises concluídas</p></div><Shield size={18} /></div>
        {totalSeverity === 0 ? <div className="chart-empty"><div className="empty-icon small"><ShieldCheck size={20} /></div><strong>Sem achados registrados</strong><span>Os resultados aparecerão aqui após uma análise.</span></div> : <div className="severity-chart">{severity.map(([name, value]) => <div className="severity-row" key={name}><div><SeverityDot severity={name} /><span>{name}</span><b>{value}</b></div><div className="bar-track"><span className={`bar-fill severity-${slug(name)}`} style={{ width: `${Math.max(value / Math.max(totalSeverity, 1) * 100, value ? 4 : 0)}%` }} /></div></div>)}</div>}
      </section>
      <section className="panel priority-panel"><div className="panel-heading"><div><h2>O que foi verificado</h2><p>Escopo da última análise</p></div><FileSearch size={18} /></div>
        {recent[0] ? <><div className="last-scan-project"><span className="project-avatar"><FileCode2 size={19} /></span><div><strong>{recent[0].project_name}</strong><span>{formatDate(recent[0].created_at)}</span></div><StatusBadge status={recent[0].status} /></div><ToolList tools={recent[0].tools} compact /></> : <div className="chart-empty"><span className="empty-icon small"><FileSearch size={19} /></span><strong>Ainda não há uma análise</strong><span>Inicie uma análise para ver o escopo e o estado das ferramentas.</span><Link to="/scans/new" className="text-link">Começar <ArrowRight size={14} /></Link></div>}
      </section>
    </div>
    <section className="panel history-panel"><div className="panel-heading"><div><h2>Análises recentes</h2><p>Histórico calculado a partir dos registros locais</p></div><Link className="text-link" to="/history">Ver histórico <ArrowRight size={14} /></Link></div>
      {recent.length ? <div className="table-wrap"><table><thead><tr><th>PROJETO</th><th>DATA</th><th>STATUS</th><th>ACHADOS</th><th>ARQUIVOS</th><th></th></tr></thead><tbody>{recent.map((scan) => <tr key={scan.id}><td><Link to={`/scans/${scan.id}`} className="project-link"><span className="table-file"><FileCode2 size={16} /></span>{scan.project_name}</Link></td><td>{formatDate(scan.created_at)}</td><td><StatusBadge status={scan.status} /></td><td><span className={scan.finding_count ? 'count-alert' : ''}>{scan.finding_count}</span></td><td>{scan.files_examined || '—'}</td><td><Link to={`/scans/${scan.id}`} className="row-arrow" aria-label={`Abrir análise ${scan.project_name}`}><ArrowUpRight size={16} /></Link></td></tr>)}</tbody></table></div> : !loading && <div className="table-empty"><span className="empty-icon"><History size={21} /></span><strong>Seu histórico começa aqui</strong><p>Quando você executar uma análise, os resultados e o estado das ferramentas ficarão disponíveis nesta área.</p><Link to="/scans/new" className="button button-secondary">Enviar primeiro projeto <ArrowRight size={15} /></Link></div>}
    </section>
    <div className="data-note"><LockKeyhole size={14} /> Resultados armazenados localmente. Nenhum dado fictício é exibido.</div>
  </>
}

function Stat({ icon, label, value, detail, tone }: { icon: ReactNode; label: string; value: string; detail: string; tone: string }) {
  return <article className="stat-card"><div className={`stat-icon ${tone}`}>{icon}</div><div className="stat-label">{label}</div><div className="stat-value">{value}</div><div className="stat-detail">{detail}</div></article>
}

function HistoryPage() {
  const [scans, setScans] = useState<Scan[]>([])
  const [error, setError] = useState('')
  const [query, setQuery] = useState('')
  const [fromDate, setFromDate] = useState('')
  const [toDate, setToDate] = useState('')
  useEffect(() => { getScans().then(setScans).catch((e: Error) => setError(e.message)) }, [])
  const filtered = scans.filter((scan) => {
    const date = scan.created_at.slice(0, 10)
    return scan.project_name.toLowerCase().includes(query.toLowerCase()) && (!fromDate || date >= fromDate) && (!toDate || date <= toDate)
  })
  return <><div className="page-heading"><div><div className="eyebrow">ATIVIDADE</div><h1>Histórico de análises</h1><p>Consulte os resultados registrados neste ambiente.</p></div><Link to="/scans/new" className="button button-primary"><Plus size={17} /> Nova análise</Link></div>
    {error && <div className="notice notice-error"><OctagonAlert size={18} /><span>{error}</span></div>}
    <div className="panel history-panel"><div className="history-toolbar"><div className="search-field"><Search size={16} /><input aria-label="Filtrar por projeto" placeholder="Filtrar por projeto…" value={query} onChange={(event) => setQuery(event.target.value)} /><kbd>/</kbd></div><div className="date-filters"><label>De <input type="date" aria-label="Data inicial" value={fromDate} onChange={(event) => setFromDate(event.target.value)} /></label><label>Até <input type="date" aria-label="Data final" value={toDate} onChange={(event) => setToDate(event.target.value)} /></label></div><span className="result-count">{filtered.length} {filtered.length === 1 ? 'análise' : 'análises'}</span></div>
      {filtered.length ? <div className="table-wrap"><table><thead><tr><th>PROJETO</th><th>DATA</th><th>STATUS</th><th>ACHADOS</th><th>ARQUIVOS</th><th>DURAÇÃO</th><th></th></tr></thead><tbody>{filtered.map((scan) => <tr key={scan.id}><td><Link to={`/scans/${scan.id}`} className="project-link"><span className="table-file"><FileCode2 size={16} /></span>{scan.project_name}</Link></td><td>{formatDate(scan.created_at)}</td><td><StatusBadge status={scan.status} /></td><td><span className={scan.finding_count ? 'count-alert' : ''}>{scan.finding_count}</span></td><td>{scan.files_examined || '—'}</td><td>{formatDuration(scan.duration_seconds)}</td><td><Link to={`/scans/${scan.id}`} className="row-arrow" aria-label="Abrir resultados"><ArrowUpRight size={16} /></Link></td></tr>)}</tbody></table></div> : <div className="table-empty"><span className="empty-icon"><History size={21} /></span><strong>{scans.length ? 'Nenhum projeto corresponde ao filtro' : 'Nenhuma análise registrada'}</strong><p>{scans.length ? 'Tente buscar outro nome de projeto.' : 'Envie um ZIP autorizado para começar.'}</p>{!scans.length && <Link to="/scans/new" className="button button-secondary">Nova análise <ArrowRight size={15} /></Link>}</div>}
    </div>
  </>
}

function NewScan() {
  const [file, setFile] = useState<File | null>(null)
  const [projectName, setProjectName] = useState('')
  const [checks, setChecks] = useState({ check_dependencies: true, check_secrets: true, check_static: true, check_configuration: true })
  const [drag, setDrag] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)
  const navigate = useNavigate()
  const choose = (chosen?: File) => {
    setError('')
    if (!chosen) return
    if (!chosen.name.toLowerCase().endsWith('.zip')) { setError('Selecione um arquivo ZIP.'); return }
    if (chosen.size > 50 * 1024 * 1024) { setError('O ZIP excede o limite de 50 MB.'); return }
    setFile(chosen)
    if (!projectName) setProjectName(chosen.name.replace(/\.zip$/i, '').replace(/[_-]+/g, ' '))
  }
  const onFile = (event: ChangeEvent<HTMLInputElement>) => choose(event.target.files?.[0])
  const onDrop = (event: DragEvent<HTMLDivElement>) => { event.preventDefault(); setDrag(false); choose(event.dataTransfer.files[0]) }
  const toggle = (key: keyof typeof checks) => setChecks((current) => ({ ...current, [key]: !current[key] }))
  const submit = async (event: FormEvent) => {
    event.preventDefault()
    if (!file) { setError('Adicione um arquivo ZIP para continuar.'); return }
    if (!Object.values(checks).some(Boolean)) { setError('Selecione ao menos uma verificação.'); return }
    setBusy(true); setError('')
    const body = new FormData(); body.append('file', file); body.append('project_name', projectName || file.name)
    Object.entries(checks).forEach(([key, value]) => body.append(key, String(value)))
    try {
      const response = await fetch(`${API}/scans`, { method: 'POST', body })
      const result = await response.json()
      if (!response.ok) throw new Error(errorMessage(result, 'Não foi possível iniciar a análise.'))
      navigate(`/scans/${result.id}`)
    } catch (e) { setError(e instanceof Error ? e.message : 'Falha ao conectar com a API.'); setBusy(false) }
  }
  const removeFile = () => { setFile(null); if (inputRef.current) inputRef.current.value = '' }
  return <><div className="page-heading"><div><div className="eyebrow">NOVA VERIFICAÇÃO</div><h1>Iniciar análise</h1><p>Envie um projeto autorizado e escolha o que deseja verificar.</p></div><Link to="/dashboard" className="button button-quiet">Cancelar</Link></div>
    <form className="new-scan-layout" onSubmit={submit}>
      <div className="new-scan-main">
        <section className="panel upload-panel"><div className="section-title-row"><span className="section-step">01</span><div><h2>Escolha o projeto</h2><p>Envie um arquivo ZIP de até 50 MB.</p></div></div>
          <input ref={inputRef} className="sr-only" type="file" accept=".zip,application/zip" onChange={onFile} aria-label="Selecionar arquivo ZIP" />
          {!file ? <div className={`dropzone ${drag ? 'dropzone-active' : ''}`} onDragEnter={(e) => { e.preventDefault(); setDrag(true) }} onDragOver={(e) => e.preventDefault()} onDragLeave={(e) => { if (e.currentTarget === e.target) setDrag(false) }} onDrop={onDrop}>
            <span className="upload-icon"><HardDriveUpload size={22} /></span><strong>Arraste seu arquivo ZIP até aqui</strong><span>ou escolha um arquivo no seu computador</span><button type="button" className="button button-secondary button-small" onClick={() => inputRef.current?.click()}>Selecionar arquivo</button><small>ZIP · limite de envio 50 MB</small>
          </div> : <div className="file-selected"><span className="file-type"><FileArchive size={19} /></span><div><strong>{file.name}</strong><span>{formatBytes(file.size)} · pronto para análise</span></div><button type="button" className="icon-button" aria-label="Remover arquivo" onClick={removeFile}><X size={17} /></button></div>}
          <label className="field-label" htmlFor="project-name">Nome do projeto</label><input id="project-name" className="text-input" maxLength={120} value={projectName} onChange={(e) => setProjectName(e.target.value)} placeholder="Ex.: api-pedidos" />
        </section>
        <section className="panel checks-panel"><div className="section-title-row"><span className="section-step">02</span><div><h2>Verificações</h2><p>Você pode alterar essas opções antes de iniciar.</p></div></div>
          <CheckRow icon={<PackageCheck />} tone="blue" title="Dependências Python" desc="Consulta requisitos com pip-audit e OSV. Não instala pacotes." checked={checks.check_dependencies} onChange={() => toggle('check_dependencies')} tag="pip-audit" />
          <CheckRow icon={<Fingerprint />} tone="violet" title="Segredos expostos" desc="Busca credenciais e tokens com regras locais; os valores são mascarados." checked={checks.check_secrets} onChange={() => toggle('check_secrets')} tag="local" />
          <CheckRow icon={<Code2 />} tone="green" title="Análise estática Python" desc="Procura padrões de risco com Bandit, se instalado no ambiente." checked={checks.check_static} onChange={() => toggle('check_static')} tag="Bandit" />
          <CheckRow icon={<Layers3 />} tone="amber" title="Configurações" desc="Verifica Dockerfile, modo debug e regras de exclusão do Git." checked={checks.check_configuration} onChange={() => toggle('check_configuration')} tag="local" />
        </section>
      </div>
      <aside className="new-scan-aside"><section className="panel review-panel"><div className="review-heading"><span className="review-shield"><ShieldCheck size={18} /></span><div><h2>Revisão da análise</h2><p>Confira antes de iniciar</p></div></div>
          <ReviewRow label="Projeto" value={projectName || file?.name.replace(/\.zip$/i, '') || 'Não selecionado'} /><ReviewRow label="Origem" value="Upload ZIP" /><ReviewRow label="Limite do arquivo" value="50 MB" /><ReviewRow label="Verificações selecionadas" value={`${Object.values(checks).filter(Boolean).length} de 4`} />
          <div className="review-notice"><LockKeyhole size={15} /><span>O conteúdo é tratado como dado. Scripts não serão executados e dependências não serão instaladas.</span></div>
          <div className="authorization-check"><ShieldHalf size={15} /><span>Confirmo que tenho autorização para examinar este projeto.</span></div>
          {error && <div className="form-error" role="alert"><OctagonAlert size={15} />{error}</div>}
          <button type="submit" className="button button-primary submit-button" disabled={busy || !file}>{busy ? <><span className="spinner" />Enviando projeto…</> : <>Iniciar análise <ArrowRight size={16} /></>}</button>
          <p className="small-print">Arquivos ignorados: <code>.git</code>, <code>node_modules</code>, <code>.venv</code>, <code>dist</code> e <code>build</code>.</p>
        </section><div className="aside-help"><CircleHelp size={16} /><span>As ferramentas opcionais ausentes serão identificadas nos resultados.</span></div>
      </aside>
    </form>
  </>
}

function CheckRow({ icon, tone, title, desc, checked, onChange, tag }: { icon: ReactNode; tone: string; title: string; desc: string; checked: boolean; onChange: () => void; tag: string }) {
  return <label className={`check-row ${!checked ? 'check-disabled' : ''}`}><span className={`check-icon ${tone}`}>{icon}</span><span className="check-copy"><strong>{title}<small>{tag}</small></strong><span>{desc}</span></span><input type="checkbox" checked={checked} onChange={onChange} aria-label={title} /><span className="toggle-track" /></label>
}
function ReviewRow({ label, value }: { label: string; value: string }) { return <div className="review-row"><span>{label}</span><strong title={value}>{value}</strong></div> }
function formatBytes(value: number) { return value < 1024 * 1024 ? `${(value / 1024).toFixed(0)} KB` : `${(value / 1024 / 1024).toFixed(1)} MB` }

function ScanDetail() {
  const { id = '' } = useParams()
  const [scan, setScan] = useState<Scan | null>(null)
  const [error, setError] = useState('')
  const [severity, setSeverity] = useState('Todas')
  const [category, setCategory] = useState('Todas')
  const [tool, setTool] = useState('Todas')
  const [query, setQuery] = useState('')
  const [exportError, setExportError] = useState('')
  const navigate = useNavigate()
  useEffect(() => {
    let alive = true
    let timer = 0
    const poll = async () => { try { const data = await getScan(id); if (alive) { setScan(data); setError(''); if (!['queued', 'analyzing', 'cancelling'].includes(data.status)) window.clearInterval(timer) } } catch (e) { if (alive) setError(e instanceof Error ? e.message : 'Erro ao consultar análise.') } }
    timer = window.setInterval(poll, 2200); poll()
    return () => { alive = false; window.clearInterval(timer) }
  }, [id])
  const findings = useMemo(() => (scan?.findings || []).filter((item) => (severity === 'Todas' || item.severity === severity) && (category === 'Todas' || item.category === category) && (tool === 'Todas' || item.tool === tool) && `${item.file || ''} ${(item.files || []).join(' ')} ${item.title} ${item.package || ''}`.toLowerCase().includes(query.toLowerCase())), [scan, severity, category, tool, query])
  const isRunning = scan && ['queued', 'analyzing', 'cancelling'].includes(scan.status)
  const exportReport = async () => {
    setExportError('')
    try { const response = await fetch(`${API}/scans/${id}/report`); const data = await response.json(); if (!response.ok) throw new Error(errorMessage(data, 'Relatório indisponível.')); const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })); const link = document.createElement('a'); link.href = url; link.download = `securescan-${id.slice(0, 8)}.json`; link.click(); URL.revokeObjectURL(url) }
    catch (e) { setExportError(e instanceof Error ? e.message : 'Falha ao exportar relatório.') }
  }
  const cancel = async () => { try { await fetch(`${API}/scans/${id}/cancel`, { method: 'POST' }); const latest = await getScan(id); setScan(latest) } catch { setError('Não foi possível solicitar o cancelamento.') } }
  if (error && !scan) return <div className="not-found"><span className="empty-icon"><OctagonAlert size={22} /></span><h1>Não foi possível abrir esta análise</h1><p>{error}</p><Link className="button button-secondary" to="/history">Voltar ao histórico</Link></div>
  if (!scan) return <div className="loading-state"><span className="spinner" /> Carregando análise…</div>
  const hasFindings = scan.finding_count > 0
  return <><div className="detail-back"><button className="back-link" onClick={() => navigate(-1)}>← Voltar</button><span>/</span><span>Análise</span><span>/</span><span>{scan.project_name}</span></div>
    <div className="page-heading scan-title-heading"><div><div className="eyebrow">RESULTADO DA ANÁLISE</div><h1>{scan.project_name}</h1><div className="scan-meta"><StatusBadge status={scan.status} /><span><Clock3 size={14} /> {formatDate(scan.created_at)}</span><span><FileCode2 size={14} /> {scan.files_examined} arquivos</span><span><Activity size={14} /> {formatDuration(scan.duration_seconds)}</span></div></div><div className="heading-actions">{isRunning && <button className="button button-quiet" onClick={cancel}>Cancelar</button>}<button className="button button-secondary" disabled={isRunning} onClick={exportReport}><ArrowDownToLine size={16} /> Exportar JSON</button></div></div>
    {isRunning && <div className="progress-panel"><span className="spinner" /><div><strong>{scan.status === 'queued' ? 'Sua análise está na fila' : 'Analisando arquivos do projeto'}</strong><span>As ferramentas podem levar alguns instantes. Esta página atualiza automaticamente.</span></div><span className="progress-pulse" /></div>}
    {scan.status === 'failed' && <div className="notice notice-error"><OctagonAlert size={18} /><div><strong>A análise não foi concluída.</strong><span>{scan.warnings.join(' ') || 'O worker não conseguiu processar o arquivo.'}</span></div></div>}
    {scan.status === 'completed_with_warnings' && <div className="notice notice-warning"><OctagonAlert size={18} /><div><strong>Análise concluída com verificações indisponíveis.</strong><span>{scan.warnings.join(' ') || 'Consulte o estado das ferramentas abaixo.'}</span></div></div>}
    {exportError && <div className="notice notice-error"><OctagonAlert size={16} /><span>{exportError}</span></div>}
    <div className="result-stats"><ResultStat label="Achados" value={String(scan.finding_count)} icon={<ShieldAlert />} tone={hasFindings ? 'red' : 'green'} /><ResultStat label="Arquivos examinados" value={String(scan.files_examined)} icon={<FileSearch />} tone="blue" /><ResultStat label="Ferramentas concluídas" value={`${scan.tools.filter((item) => item.status === 'completed').length}/${scan.tools.length}`} icon={<BadgeCheck />} tone="violet" /><ResultStat label="Duração" value={formatDuration(scan.duration_seconds)} icon={<Clock3 />} tone="amber" /></div>
    <div className="detail-grid"><section className="panel tools-panel"><div className="panel-heading"><div><h2>Verificações executadas</h2><p>Estado das ferramentas para esta análise</p></div><Activity size={18} /></div><ToolList tools={scan.tools} />{!scan.tools.length && <div className="tool-wait"><span className="spinner" /> Aguardando início…</div>}</section>
      <section className="panel distribution-panel"><div className="panel-heading"><div><h2>Distribuição por gravidade</h2><p>Classificação dos achados encontrados</p></div><Shield size={18} /></div>{severityNames.map((name) => <div className="distribution-row" key={name}><span><SeverityDot severity={name} />{name}</span><strong>{scan.severity_counts[name] || 0}</strong></div>)}</section></div>
    {scan.status !== 'queued' && scan.status !== 'analyzing' && <section className="panel findings-panel"><div className="panel-heading"><div><h2>Achados</h2><p>{scan.finding_count ? 'Revise o contexto e valide cada resultado.' : 'Nenhum achado foi produzido pelas verificações executadas.'}</p></div><span className="findings-total">{scan.finding_count} total</span></div>
      {!hasFindings ? <div className="no-findings"><span className="empty-icon success"><ShieldCheck size={23} /></span><div><strong>Nenhum achado reportado</strong><p>Isso não comprova que o projeto esteja livre de vulnerabilidades. Confira também as ferramentas marcadas como indisponíveis ou ignoradas.</p></div></div> : <>
        <div className="findings-filters"><div className="filter-select"><label htmlFor="severity-filter">Gravidade</label><select id="severity-filter" value={severity} onChange={(e) => setSeverity(e.target.value)}><option>Todas</option>{severityNames.map((s) => <option key={s}>{s}</option>)}</select></div><div className="filter-select"><label htmlFor="category-filter">Categoria</label><select id="category-filter" value={category} onChange={(e) => setCategory(e.target.value)}><option>Todas</option>{Object.entries(categoryNames).map(([key, label]) => <option value={key} key={key}>{label}</option>)}</select></div><div className="filter-select"><label htmlFor="tool-filter">Ferramenta</label><select id="tool-filter" value={tool} onChange={(e) => setTool(e.target.value)}><option>Todas</option>{[...new Set(scan.findings.map((item) => item.tool))].map((name) => <option key={name}>{name}</option>)}</select></div><div className="search-field finding-search"><Search size={15} /><input aria-label="Filtrar por arquivo ou pacote" placeholder="Arquivo, pacote…" value={query} onChange={(e) => setQuery(e.target.value)} /></div><span className="result-count">{findings.length} de {scan.finding_count}</span></div>
        {findings.length ? <div className="findings-list">{findings.map((finding) => <FindingCard finding={finding} key={finding.id} />)}</div> : <div className="filter-empty">Nenhum achado corresponde aos filtros selecionados.</div>}
      </>}
    </section>}
    <div className="report-disclaimer"><ShieldHalf size={15} /><span>Resultados estáticos precisam de validação contextual. Um resultado sem achados não é garantia de segurança.</span><button onClick={exportReport} className="text-link">Baixar relatório JSON <ArrowRight size={14} /></button></div>
  </>
}

function ResultStat({ label, value, icon, tone }: { label: string; value: string; icon: ReactNode; tone: string }) { return <div className="result-stat"><span className={`result-stat-icon ${tone}`}>{icon}</span><div><span>{label}</span><strong>{value}</strong></div></div> }
function ToolList({ tools, compact = false }: { tools: ToolResult[]; compact?: boolean }) {
  const labels: Record<string, string> = { completed: 'Concluída', unavailable: 'Indisponível', failed: 'Falhou', timeout: 'Tempo esgotado', skipped: 'Ignorada', not_selected: 'Não selecionada', cancelled: 'Cancelada' }
  return <div className={`tool-list ${compact ? 'tool-list-compact' : ''}`}>{tools.map((tool) => <div className="tool-row" key={tool.name}><span className={`tool-state ${tool.status === 'completed' ? 'tool-ok' : tool.status === 'unavailable' || tool.status === 'failed' || tool.status === 'timeout' ? 'tool-warn' : ''}`}>{tool.status === 'completed' ? <Check size={13} /> : tool.status === 'unavailable' || tool.status === 'failed' || tool.status === 'timeout' ? <OctagonAlert size={13} /> : <Clock3 size={13} />}</span><div><strong>{tool.name}</strong>{!compact && <span>{tool.details || tool.version || (tool.status === 'unavailable' ? 'Instale a ferramenta para habilitar esta verificação.' : '')}</span>}</div><span className={`tool-status-text ${tool.status === 'completed' ? 'text-ok' : tool.status === 'unavailable' || tool.status === 'failed' || tool.status === 'timeout' ? 'text-warn' : ''}`}>{labels[tool.status] || tool.status}</span></div>)}</div>
}
function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false)
  return <article className={`finding-card ${open ? 'finding-open' : ''}`}><button className="finding-main" onClick={() => setOpen(!open)} aria-expanded={open}><span className={`severity-pill severity-${slug(finding.severity)}`}><SeverityDot severity={finding.severity} />{finding.severity}</span><span className="finding-summary"><strong>{finding.title}</strong><span>{finding.file || finding.package || 'Projeto'}{finding.line ? `:${finding.line}` : ''} <span className="finding-divider">·</span> {categoryNames[finding.category] || finding.category} <span className="finding-divider">·</span> {finding.tool}</span></span>{finding.vulnerability_id && <span className="finding-id">{finding.vulnerability_id}</span>}<ChevronDown size={17} className="finding-chevron" /></button>
    {open && <div className="finding-detail"><p>{finding.description}</p>{finding.evidence && <pre className="evidence"><code>{finding.evidence}</code></pre>}<div className="finding-facts">{finding.package && <Fact label="Pacote" value={`${finding.package}${finding.version ? ` ${finding.version}` : ''}`} />}{finding.files && finding.files.length > 1 && <Fact label="Arquivos de origem" value={finding.files.join(', ')} />}{finding.fixed_version && <Fact label="Versão corrigida" value={finding.fixed_version} />}{finding.rule && <Fact label="Regra" value={finding.rule} />}{finding.original_severity && <Fact label="Severidade da fonte" value={finding.original_severity} />}{finding.confidence && <Fact label="Confiança" value={finding.confidence} />}</div>{finding.remediation && <div className="remediation"><strong><Sparkles size={14} /> Recomendação</strong><span>{finding.remediation}</span></div>}{finding.references?.length ? <div className="finding-references">{finding.references.map((url) => <a key={url} href={url} target="_blank" rel="noreferrer">Documentação oficial <ArrowUpRight size={13} /></a>)}</div> : null}<div className="false-positive-note"><CircleHelp size={14} /> A detecção é estática e pode exigir validação contextual.</div></div>}
  </article>
}
function Fact({ label, value }: { label: string; value: string }) { return <div className="finding-fact"><span>{label}</span><strong>{value}</strong></div> }
function SeverityDot({ severity }: { severity: string }) { return <span className={`severity-dot severity-${slug(severity)}`} /> }
function StatusBadge({ status }: { status: string }) { return <span className={`status-badge status-${slug(status)}`}><span />{statusNames[status] || status}</span> }
function slug(value: string) { return value.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]+/g, '-') }

function NotFound() { return <div className="not-found"><span className="empty-icon"><FileSearch size={22} /></span><h1>Página não encontrada</h1><p>Esse endereço não corresponde a uma página do SecureScan.</p><Link to="/dashboard" className="button button-secondary">Ir para o painel</Link></div> }

export default function App() {
  return <Routes><Route path="/" element={<Landing />} /><Route element={<Workspace />}><Route path="/dashboard" element={<Dashboard />} /><Route path="/history" element={<HistoryPage />} /><Route path="/scans/new" element={<NewScan />} /><Route path="/scans/:id" element={<ScanDetail />} /><Route path="*" element={<NotFound />} /></Route></Routes>
}
