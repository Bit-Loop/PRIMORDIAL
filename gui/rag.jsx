/* global React, Pill, Panel, Field */
const { useState: useStateR, useEffect: useEffectR, useMemo: useMemoR } = React;

function asArray(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value.map(item => String(item).trim()).filter(Boolean);
  return String(value).split(',').map(item => item.trim()).filter(Boolean);
}

function shortValue(value, left = 12, right = 8) {
  const text = String(value || '');
  if (text.length <= left + right + 3) return text;
  return `${text.slice(0, left)}...${text.slice(-right)}`;
}

function ragResultMeta(row) {
  const metadata = row?.metadata && typeof row.metadata === 'object' ? row.metadata : {};
  return {
    sourceFile: metadata.source_file || row?.source_file || '',
    domain: metadata.domain || metadata.corpus_type || row?.domain || '',
    section: metadata.section || row?.section || '',
    page: metadata.page_start || metadata.page_end
      ? `${metadata.page_start || '?'}-${metadata.page_end || metadata.page_start || '?'}`
      : '',
    docId: metadata.doc_id || row?.doc_id || '',
  };
}

function RagMode() {
  const API = window.PD_API || {};
  const [status, setStatus] = useStateR(null);
  const [config, setConfig] = useStateR(null);
  const [vulnStatus, setVulnStatus] = useStateR(null);
  const [busy, setBusy] = useStateR('');
  const [error, setError] = useStateR('');
  const [importForm, setImportForm] = useStateR({
    chunks_dir: '',
    dry_run: true,
    force: false,
    reembed: false,
    skip_embeddings: false,
    domain: '',
    source_file: '',
    doc_id: '',
    limit: '',
  });
  const [importResult, setImportResult] = useStateR(null);
  const [searchForm, setSearchForm] = useStateR({
    query: 'BOLA authorization checklist',
    domain: 'api_security',
    source_file: '',
    doc_id: '',
    chunk_type: '',
    limit: 5,
  });
  const [searchResult, setSearchResult] = useStateR(null);
  const [chunkDetail, setChunkDetail] = useStateR(null);
  const [sourceProfile, setSourceProfile] = useStateR(null);
  const [synthesis, setSynthesis] = useStateR(null);
  const [citationTab, setCitationTab] = useStateR('readable');
  const [evalQueries, setEvalQueries] = useStateR('What is the difference between BOLA and BFLA?\nMap this finding to OWASP and MITRE ATT&CK.');
  const [evalResult, setEvalResult] = useStateR(null);
  const [vulnSyncForm, setVulnSyncForm] = useStateR({
    since_year: 2020,
    embed_all: true,
    sources: 'nvd, kev, epss, cvelist_v5, osv, ghsa',
    max_enrichment_cves: 250,
    max_nvd_pages: '',
    skip_embeddings: false,
  });
  const [vulnSyncResult, setVulnSyncResult] = useStateR(null);
  const [vulnSearchForm, setVulnSearchForm] = useStateR({
    query: 'OpenSSH CVE patch remediation',
    cve_id: '',
    ghsa_id: '',
    osv_id: '',
    package: '',
    ecosystem: '',
    kev: false,
    epss_percentile: '',
    limit: 8,
  });
  const [vulnSearchResult, setVulnSearchResult] = useStateR(null);
  const [vulnHints, setVulnHints] = useStateR(null);

  const results = useMemoR(() => searchResult?.results || [], [searchResult]);
  const vulnResults = useMemoR(() => vulnSearchResult?.results || [], [vulnSearchResult]);
  const selectedChunk = chunkDetail?.chunk || null;
  const selectedMetadata = selectedChunk?.metadata || {};

  async function loadStatus() {
    setBusy('status');
    setError('');
    try {
      const nextStatus = API.ragStatus ? await API.ragStatus() : await API.request('/api/rag/status');
      const nextConfig = API.ragConfig ? await API.ragConfig() : await API.request('/api/rag/config');
      const nextVulnStatus = API.ragVulnStatus ? await API.ragVulnStatus() : await API.request('/api/rag/vuln/status');
      setStatus(nextStatus);
      setConfig(nextConfig);
      setVulnStatus(nextVulnStatus);
      if (!importForm.chunks_dir && nextConfig?.default_chunks_dir) {
        setImportForm(prev => ({ ...prev, chunks_dir: nextConfig.default_chunks_dir }));
      }
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setBusy('');
    }
  }

  useEffectR(() => {
    loadStatus();
  }, []);

  function updateImport(key, value) {
    setImportForm(prev => ({ ...prev, [key]: value }));
  }

  function updateSearch(key, value) {
    setSearchForm(prev => ({ ...prev, [key]: value }));
  }

  function updateVulnSync(key, value) {
    setVulnSyncForm(prev => ({ ...prev, [key]: value }));
  }

  function updateVulnSearch(key, value) {
    setVulnSearchForm(prev => ({ ...prev, [key]: value }));
  }

  function searchPayload() {
    return {
      query: searchForm.query,
      limit: Number(searchForm.limit || 5),
      domain: asArray(searchForm.domain),
      source_file: asArray(searchForm.source_file),
      doc_id: asArray(searchForm.doc_id),
      chunk_type: asArray(searchForm.chunk_type),
    };
  }

  function vulnSearchPayload() {
    const payload = {
      query: vulnSearchForm.query,
      limit: Number(vulnSearchForm.limit || 8),
      cve_id: asArray(vulnSearchForm.cve_id),
      ghsa_id: asArray(vulnSearchForm.ghsa_id),
      osv_id: asArray(vulnSearchForm.osv_id),
      package: asArray(vulnSearchForm.package),
      ecosystem: asArray(vulnSearchForm.ecosystem),
    };
    if (vulnSearchForm.kev) payload.kev = true;
    if (vulnSearchForm.epss_percentile) payload.epss_percentile = { gte: Number(vulnSearchForm.epss_percentile) };
    return payload;
  }

  async function runVulnSync() {
    setBusy('vuln-sync');
    setError('');
    try {
      const payload = {
        since_year: Number(vulnSyncForm.since_year || 2020),
        embed_all: !!vulnSyncForm.embed_all,
        sources: asArray(vulnSyncForm.sources),
        max_enrichment_cves: Number(vulnSyncForm.max_enrichment_cves || 250),
        max_nvd_pages: vulnSyncForm.max_nvd_pages ? Number(vulnSyncForm.max_nvd_pages) : undefined,
        skip_embeddings: !!vulnSyncForm.skip_embeddings,
      };
      const response = API.ragVulnSync
        ? await API.ragVulnSync(payload)
        : await API.request('/api/rag/vuln/sync', { method: 'POST', body: payload, timeoutMs: 1200000 });
      setVulnSyncResult(response.result || response);
      await loadStatus();
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setBusy('');
    }
  }

  async function runVulnSearch() {
    setBusy('vuln-search');
    setError('');
    try {
      const payload = await (API.ragVulnSearch
        ? API.ragVulnSearch(vulnSearchPayload())
        : API.request('/api/rag/vuln/search', { method: 'POST', body: vulnSearchPayload() }));
      setVulnSearchResult(payload);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setBusy('');
    }
  }

  async function runVulnHints() {
    setBusy('vuln-hints');
    setError('');
    try {
      const payload = await (API.ragVulnHints
        ? API.ragVulnHints(vulnSearchPayload())
        : API.request('/api/rag/vuln/hints', { method: 'POST', body: vulnSearchPayload() }));
      setVulnHints(payload);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setBusy('');
    }
  }

  async function runImport() {
    setBusy('import');
    setError('');
    try {
      const payload = {
        chunks_dir: importForm.chunks_dir,
        dry_run: !!importForm.dry_run,
        force: !!importForm.force,
        reembed: !!importForm.reembed,
        skip_embeddings: !!importForm.skip_embeddings,
        domain: asArray(importForm.domain),
        source_file: asArray(importForm.source_file),
        doc_id: asArray(importForm.doc_id),
        limit: importForm.limit ? Number(importForm.limit) : undefined,
      };
      const response = API.ragImport ? await API.ragImport(payload) : await API.request('/api/rag/import', { method: 'POST', body: payload, timeoutMs: 600000 });
      setImportResult(response.result || response);
      await loadStatus();
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setBusy('');
    }
  }

  async function runSearch() {
    if (!searchForm.query.trim()) return;
    setBusy('search');
    setError('');
    try {
      const payload = await (API.ragSearch
        ? API.ragSearch(searchPayload())
        : API.request('/api/rag/search', { method: 'POST', body: searchPayload() }));
      setSearchResult(payload);
      setSynthesis(null);
      setChunkDetail(null);
      setSourceProfile(null);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setBusy('');
    }
  }

  async function inspectRow(row) {
    const chunkId = row?.citation_id || row?.chunk_id;
    const meta = ragResultMeta(row);
    if (!chunkId) return;
    setBusy('inspect');
    setError('');
    try {
      const detail = await (API.ragInspectChunk
        ? API.ragInspectChunk(chunkId)
        : API.request(`/api/rag/chunks/${encodeURIComponent(chunkId)}`));
      setChunkDetail(detail);
      if (meta.docId) {
        const profile = await (API.ragSourceProfile
          ? API.ragSourceProfile(meta.docId)
          : API.request(`/api/rag/sources/${encodeURIComponent(meta.docId)}`));
        setSourceProfile(profile);
      }
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setBusy('');
    }
  }

  async function runSynthesis() {
    if (!searchForm.query.trim()) return;
    setBusy('synthesize');
    setError('');
    try {
      const payload = await (API.ragSynthesize
        ? API.ragSynthesize({ query: searchForm.query, mode: 'grounded_answer', retrieved_chunks: results })
        : API.request('/api/rag/synthesize', { method: 'POST', body: { query: searchForm.query, mode: 'grounded_answer', retrieved_chunks: results }, timeoutMs: 180000 }));
      setSynthesis(payload);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setBusy('');
    }
  }

  async function runEval() {
    setBusy('eval');
    setError('');
    try {
      const payload = await (API.ragEval
        ? API.ragEval({ queries: evalQueries, limit: Number(searchForm.limit || 5), domain: asArray(searchForm.domain) })
        : API.request('/api/rag/eval', { method: 'POST', body: { queries: evalQueries, limit: Number(searchForm.limit || 5), domain: asArray(searchForm.domain) } }));
      setEvalResult(payload);
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setBusy('');
    }
  }

  const embeddingModel = status?.embedding_models?.[0] || {};
  const lastImport = status?.last_import || {};
  const validation = synthesis?.validation || {};
  const citationMap = synthesis?.citation_map || searchResult?.citation_map || [];
  const citedIds = new Set(validation.cited_ids || []);

  return (
    <>
      <div className="mode-topbar">
        <div className="crumbs"><span>PRIMORDIAL</span><span className="sep">/</span><span className="crumb">RAG</span></div>
        <div className="right">
          <div className="stats">
            <span className="stat"><span className="stat-k">chunks</span><span className="stat-v mono">{status?.document_chunks ?? 0}</span></span>
            <span className="stat"><span className="stat-k">vuln</span><span className="stat-v mono">{vulnStatus?.vuln_intel_chunks ?? 0}</span></span>
            <span className="stat"><span className="stat-k">embeddings</span><span className="stat-v mono">{status?.record_embeddings ?? 0}</span></span>
            <span className="stat"><span className="stat-k">model</span><span className="stat-v mono">{embeddingModel.model || status?.configured_embeddings?.model || 'unknown'}</span></span>
          </div>
          <button className="btn ghost sm" onClick={loadStatus} disabled={!!busy}>{busy === 'status' ? 'REFRESHING' : 'REFRESH'}</button>
        </div>
      </div>

      {error && (
        <div className="pd-live-switch">
          <span className="pd-error mono">{error}</span>
          <button className="btn ghost sm" onClick={() => setError('')}>CLEAR</button>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: '1.05fr 1.35fr 1fr', gap: 12, padding: 12, height: 'calc(100vh - 58px)', minHeight: 0 }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, minHeight: 0, overflow: 'auto' }}>
          <Panel title="Corpus Status" sub={`${status?.record_embeddings ?? 0}/${status?.document_chunks ?? 0} embedded`}>
            <div className="kpi-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
              <div><div className="kpi-k">document chunks</div><div className="mono strong">{status?.document_chunks ?? 0}</div></div>
              <div><div className="kpi-k">record embeddings</div><div className="mono strong">{status?.record_embeddings ?? 0}</div></div>
              <div><div className="kpi-k">vuln chunks</div><div className="mono strong">{vulnStatus?.vuln_intel_chunks ?? 0}</div></div>
              <div><div className="kpi-k">dimension</div><div className="mono strong">{embeddingModel.dimension || status?.configured_embeddings?.dimension || 'unknown'}</div></div>
              <div><div className="kpi-k">failures</div><div className="mono strong">{lastImport.failures ?? 0}</div></div>
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 10 }}>
              {(status?.domains || []).map(item => <Pill key={item.domain} tone="cyan">{item.domain}:{item.count}</Pill>)}
            </div>
            <div className="dim mono" style={{ marginTop: 10 }}>last import {lastImport.completed_at || 'none'}</div>
          </Panel>

          <Panel title="CVE/Vuln Sync" sub={busy === 'vuln-sync' ? 'syncing official feeds' : (vulnStatus?.last_vuln_sync?.completed_at || 'not synced')}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              <Field label="since year"><input className="input" type="number" value={vulnSyncForm.since_year} onChange={e => updateVulnSync('since_year', e.target.value)} /></Field>
              <Field label="max enrich"><input className="input" type="number" value={vulnSyncForm.max_enrichment_cves} onChange={e => updateVulnSync('max_enrichment_cves', e.target.value)} /></Field>
            </div>
            <Field label="sources"><input className="input" value={vulnSyncForm.sources} onChange={e => updateVulnSync('sources', e.target.value)} /></Field>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              <Field label="max nvd pages"><input className="input" type="number" value={vulnSyncForm.max_nvd_pages} onChange={e => updateVulnSync('max_nvd_pages', e.target.value)} placeholder="full" /></Field>
              <label className="dim mono" style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: 10.5, marginTop: 18 }}>
                <input type="checkbox" checked={!!vulnSyncForm.embed_all} onChange={e => updateVulnSync('embed_all', e.target.checked)} />
                EMBED ALL CARDS
              </label>
            </div>
            <label className="dim mono" style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: 10.5, marginTop: 8 }}>
              <input type="checkbox" checked={!!vulnSyncForm.skip_embeddings} onChange={e => updateVulnSync('skip_embeddings', e.target.checked)} />
              SKIP VECTOR EMBEDDINGS
            </label>
            <button className="btn primary sm" onClick={runVulnSync} disabled={busy === 'vuln-sync'} style={{ marginTop: 8 }}>
              {busy === 'vuln-sync' ? 'SYNCING' : 'SYNC VULN RAG'}
            </button>
            {vulnSyncResult && (
              <pre className="mono" style={{ margin: '10px 0 0', maxHeight: 150, overflow: 'auto', fontSize: 10.5, whiteSpace: 'pre-wrap' }}>{JSON.stringify({
                chunks: vulnSyncResult.vuln_intel_chunks,
                sources: vulnSyncResult.sync?.sources,
                import: vulnSyncResult.import,
              }, null, 2)}</pre>
            )}
          </Panel>

          <Panel title="Import/Reindex Controls" sub={busy === 'import' ? 'running' : 'ready'}>
            <Field label="chunks dir"><input className="input" value={importForm.chunks_dir} onChange={e => updateImport('chunks_dir', e.target.value)} /></Field>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              <Field label="domain"><input className="input" value={importForm.domain} onChange={e => updateImport('domain', e.target.value)} /></Field>
              <Field label="limit"><input className="input" type="number" value={importForm.limit} onChange={e => updateImport('limit', e.target.value)} /></Field>
              <Field label="source file"><input className="input" value={importForm.source_file} onChange={e => updateImport('source_file', e.target.value)} /></Field>
              <Field label="doc id"><input className="input" value={importForm.doc_id} onChange={e => updateImport('doc_id', e.target.value)} /></Field>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, marginTop: 8 }}>
              {[
                ['dry_run', 'DRY RUN'],
                ['force', 'FORCE'],
                ['reembed', 'REEMBED'],
                ['skip_embeddings', 'SKIP EMBEDDINGS'],
              ].map(([key, label]) => (
                <label key={key} className="dim mono" style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: 10.5 }}>
                  <input type="checkbox" checked={!!importForm[key]} onChange={e => updateImport(key, e.target.checked)} />
                  {label}
                </label>
              ))}
            </div>
            <button className="btn primary sm" onClick={runImport} disabled={busy === 'import'} style={{ marginTop: 8 }}>
              {busy === 'import' ? 'IMPORTING' : 'RUN IMPORT'}
            </button>
            {importResult && (
              <pre className="mono" style={{ margin: '10px 0 0', maxHeight: 150, overflow: 'auto', fontSize: 10.5, whiteSpace: 'pre-wrap' }}>{JSON.stringify(importResult, null, 2)}</pre>
            )}
          </Panel>

          <Panel title="Model Config" sub={config?.synthesis?.model || 'not loaded'}>
            <div className="dim mono" style={{ fontSize: 11, overflowWrap: 'anywhere' }}>
              embeddings {config?.embeddings?.provider}:{config?.embeddings?.model}<br />
              synthesis {config?.synthesis?.provider}:{config?.synthesis?.model}<br />
              disallowed {(config?.synthesis?.disallowed_models || []).join(', ') || 'none'}<br />
              default {config?.default_chunks_dir || ''}
            </div>
          </Panel>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, minHeight: 0 }}>
          <Panel title="Vulnerability Intel" sub={`${vulnResults.length} cards`} actions={
            <div style={{ display: 'flex', gap: 6 }}>
              <button className="btn sm" onClick={runVulnSearch} disabled={busy === 'vuln-search'}>{busy === 'vuln-search' ? 'SEARCHING' : 'SEARCH'}</button>
              <button className="btn ghost sm" onClick={runVulnHints} disabled={busy === 'vuln-hints'}>{busy === 'vuln-hints' ? 'RUNNING' : 'HINTS'}</button>
            </div>
          }>
            <Field label="query"><input className="input" value={vulnSearchForm.query} onChange={e => updateVulnSearch('query', e.target.value)} onKeyDown={e => { if (e.key === 'Enter') runVulnSearch(); }} /></Field>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 80px', gap: 8 }}>
              <Field label="CVE"><input className="input" value={vulnSearchForm.cve_id} onChange={e => updateVulnSearch('cve_id', e.target.value)} /></Field>
              <Field label="package"><input className="input" value={vulnSearchForm.package} onChange={e => updateVulnSearch('package', e.target.value)} /></Field>
              <Field label="limit"><input className="input" type="number" value={vulnSearchForm.limit} onChange={e => updateVulnSearch('limit', e.target.value)} /></Field>
              <Field label="GHSA"><input className="input" value={vulnSearchForm.ghsa_id} onChange={e => updateVulnSearch('ghsa_id', e.target.value)} /></Field>
              <Field label="ecosystem"><input className="input" value={vulnSearchForm.ecosystem} onChange={e => updateVulnSearch('ecosystem', e.target.value)} /></Field>
              <Field label="EPSS gte"><input className="input" type="number" step="0.01" value={vulnSearchForm.epss_percentile} onChange={e => updateVulnSearch('epss_percentile', e.target.value)} /></Field>
            </div>
            <label className="dim mono" style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: 10.5, marginTop: 8 }}>
              <input type="checkbox" checked={!!vulnSearchForm.kev} onChange={e => updateVulnSearch('kev', e.target.checked)} />
              KEV ONLY
            </label>
            <div style={{ display: 'grid', gap: 8, maxHeight: 250, overflow: 'auto', marginTop: 10 }}>
              {vulnResults.map(row => {
                const metadata = row.metadata && typeof row.metadata === 'object' ? row.metadata : {};
                return (
                  <button key={row.citation_id || row.chunk_id} className="btn ghost" onClick={() => inspectRow(row)} style={{ textAlign: 'left', justifyContent: 'flex-start', display: 'block', whiteSpace: 'normal' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                      <strong>{metadata.cve_id || metadata.vuln_id || row.title || row.chunk_id}</strong>
                      <span className="mono dim">{row.citation_id}</span>
                    </div>
                    <div className="dim mono" style={{ fontSize: 10.5 }}>
                      {metadata.card_type || 'card'} · {metadata.cvss_severity || 'severity unknown'} · KEV {metadata.kev ? 'yes' : 'no'} · EPSS {metadata.epss_percentile ?? 'n/a'}
                    </div>
                  </button>
                );
              })}
              {!vulnResults.length && <div className="dim">No vulnerability cards returned yet.</div>}
            </div>
            {vulnHints && (
              <pre className="mono" style={{ margin: '10px 0 0', maxHeight: 120, overflow: 'auto', fontSize: 10.5, whiteSpace: 'pre-wrap' }}>{JSON.stringify({
                policy: vulnHints.policy,
                hints: vulnHints.hints,
              }, null, 2)}</pre>
            )}
          </Panel>

          <Panel title="Search" sub={`${results.length} retrieved`} actions={<button className="btn sm" onClick={runSearch} disabled={busy === 'search'}>{busy === 'search' ? 'SEARCHING' : 'SEARCH'}</button>}>
            <Field label="query"><input className="input" value={searchForm.query} onChange={e => updateSearch('query', e.target.value)} onKeyDown={e => { if (e.key === 'Enter') runSearch(); }} /></Field>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 80px', gap: 8 }}>
              <Field label="domain"><input className="input" value={searchForm.domain} onChange={e => updateSearch('domain', e.target.value)} /></Field>
              <Field label="source file"><input className="input" value={searchForm.source_file} onChange={e => updateSearch('source_file', e.target.value)} /></Field>
              <Field label="limit"><input className="input" type="number" value={searchForm.limit} onChange={e => updateSearch('limit', e.target.value)} /></Field>
            </div>
          </Panel>

          <Panel title="Retrieved Chunks" bodyClass="no-pad" className="flex-panel">
            <div style={{ minHeight: 0, overflow: 'auto' }}>
              <table className="t">
                <thead>
                  <tr><th>SOURCE</th><th>CHUNK</th><th>SCORE</th><th>DOMAIN</th><th>SECTION/PAGE</th><th>CITATION</th></tr>
                </thead>
                <tbody>
                  {results.map(row => {
                    const meta = ragResultMeta(row);
                    return (
                      <tr key={row.citation_id || row.chunk_id} onClick={() => inspectRow(row)} style={{ cursor: 'pointer' }}>
                        <td title={meta.sourceFile}>{shortValue(meta.sourceFile, 16, 8)}</td>
                        <td className="mono">{shortValue(row.chunk_id, 10, 6)}</td>
                        <td className="mono">{row.score}</td>
                        <td>{meta.domain}</td>
                        <td title={meta.section}>{shortValue(meta.section || meta.page, 22, 8)}</td>
                        <td className="mono">{shortValue(row.citation_id, 12, 6)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </Panel>

          <Panel title="Answer Citations" sub={synthesis?.status || 'not run'} actions={<button className="btn sm" onClick={runSynthesis} disabled={!results.length || busy === 'synthesize'}>{busy === 'synthesize' ? 'RUNNING' : 'SYNTHESIZE'}</button>}>
            <div style={{ display: 'flex', gap: 6, marginBottom: 8 }}>
              <button className={`btn ghost sm ${citationTab === 'readable' ? 'active' : ''}`} onClick={() => setCitationTab('readable')}>READABLE</button>
              <button className={`btn ghost sm ${citationTab === 'raw' ? 'active' : ''}`} onClick={() => setCitationTab('raw')}>RAW</button>
            </div>
            {citationTab === 'readable' ? (
              <>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                  <div><div className="kpi-k">retrieved ids</div><div className="mono strong">{(synthesis?.retrieved_ids || results.map(row => row.citation_id)).filter(Boolean).length}</div></div>
                  <div><div className="kpi-k">cited ids</div><div className="mono strong">{(validation.cited_ids || []).length}</div></div>
                </div>
                <pre className="mono" style={{ margin: '10px 0 0', maxHeight: 145, overflow: 'auto', fontSize: 10.5, whiteSpace: 'pre-wrap' }}>{synthesis?.answer || 'Run synthesis to validate cited answer text. Search results below are still inspectable source context.'}</pre>
                {synthesis && (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 8 }}>
                    <Pill tone={validation.valid ? 'green' : 'amber'}>{validation.valid ? 'VALID' : 'CHECK'}</Pill>
                    {(validation.invented_ids || []).length ? <Pill tone="red">invented {(validation.invented_ids || []).length}</Pill> : null}
                    {(validation.missing_citations || []).length ? <Pill tone="amber">missing citations</Pill> : null}
                    {(validation.blocked_source_use || []).length ? <Pill tone="red">blocked source use</Pill> : null}
                  </div>
                )}
                <div style={{ marginTop: 10, display: 'grid', gap: 8 }}>
                  {citationMap.length ? citationMap.map(item => (
                    <div key={item.citation_id || item.chunk_id} style={{ border: '1px solid rgba(255,255,255,0.12)', borderRadius: 8, padding: 8, background: 'rgba(255,255,255,0.03)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                        <strong>{item.source_display || item.title || item.source_file || item.chunk_id}</strong>
                        <span className="mono dim">{item.citation_id}</span>
                      </div>
                      <div className="dim mono" style={{ fontSize: 10.5 }}>
                        {item.domain || 'unknown'} · {item.usage_policy || 'advisory'} · {item.section || item.source_file || 'source'}
                        {item.page_start ? ` · p.${item.page_start}${item.page_end && item.page_end !== item.page_start ? `-${item.page_end}` : ''}` : ''}
                      </div>
                      <div className="dim" style={{ marginTop: 4 }}>{shortValue(item.excerpt, 140, 28)}</div>
                      {synthesis ? <Pill tone={citedIds.has(item.citation_id) ? 'green' : 'gray'}>{citedIds.has(item.citation_id) ? 'cited' : 'retrieved only'}</Pill> : null}
                    </div>
                  )) : <div className="dim">No citation map yet. Run a search or synthesis.</div>}
                </div>
              </>
            ) : (
              <pre className="mono" style={{ margin: '8px 0 0', maxHeight: 360, overflow: 'auto', fontSize: 10.5, whiteSpace: 'pre-wrap' }}>{JSON.stringify({ validation, citation_map: citationMap, synthesis }, null, 2)}</pre>
            )}
          </Panel>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, minHeight: 0, overflow: 'auto' }}>
          <Panel title="Retrieved Chunk Inspector" sub={selectedChunk?.citation_id || selectedChunk?.id || 'none'}>
            <div className="dim mono" style={{ fontSize: 10.5, overflowWrap: 'anywhere' }}>
              source {selectedMetadata.source_file || 'none'}<br />
              doc {selectedMetadata.doc_id || 'none'}<br />
              embedding {chunkDetail?.embedding?.embedding_model || 'none'} dim {chunkDetail?.embedding?.embedding_dim || 'none'}
            </div>
            <pre className="mono" style={{ margin: '10px 0 0', maxHeight: 260, overflow: 'auto', fontSize: 10.5, whiteSpace: 'pre-wrap' }}>{selectedChunk?.text || 'Select a retrieved chunk.'}</pre>
          </Panel>

          <Panel title="Source Profiles" sub={sourceProfile?.doc_id || 'none'}>
            <div className="dim mono" style={{ fontSize: 10.5, overflowWrap: 'anywhere' }}>
              title {sourceProfile?.title || 'none'}<br />
              file {sourceProfile?.source_file || 'none'}<br />
              sha {shortValue(sourceProfile?.source_sha256, 16, 10)}<br />
              chunks {sourceProfile?.chunk_count ?? 0}<br />
              domains {(sourceProfile?.domains || []).join(', ') || 'none'}
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 8 }}>
              {(sourceProfile?.sections || []).slice(0, 8).map(section => <Pill key={section} tone="gray">{shortValue(section, 24, 6)}</Pill>)}
            </div>
          </Panel>

          <Panel title="Evaluation Probes" sub={evalResult ? `${evalResult.query_count} queries` : 'ready'} actions={<button className="btn sm" onClick={runEval} disabled={busy === 'eval'}>{busy === 'eval' ? 'RUNNING' : 'RUN'}</button>}>
            <textarea className="input" value={evalQueries} onChange={e => setEvalQueries(e.target.value)} style={{ minHeight: 96, resize: 'vertical', fontFamily: 'var(--mono)', fontSize: 11 }} />
            {evalResult && (
              <pre className="mono" style={{ margin: '10px 0 0', maxHeight: 220, overflow: 'auto', fontSize: 10.5, whiteSpace: 'pre-wrap' }}>{JSON.stringify(evalResult.results, null, 2)}</pre>
            )}
          </Panel>
        </div>
      </div>
    </>
  );
}

window.RagMode = RagMode;
