import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve('.');
const sourceDir = resolve(root, 'gui');
const outDir = resolve(root, 'primordial/core/web/frontend/src');
const outFile = resolve(outDir, 'generated-gui.jsx');

const sources = [
  'tweaks-panel.jsx',
  'atoms.jsx',
  'dashboard.jsx',
  'map.jsx',
  'chat.jsx',
  'pair.jsx',
  'notion.jsx',
  'interests.jsx',
  'caido.jsx',
  'rag.jsx',
  'app.jsx',
];

const aliasesBySource = {
  'dashboard.jsx': ['Pill', 'Dot', 'StatusPill', 'Panel', 'Field'],
  'map.jsx': ['Pill', 'Dot', 'Panel'],
  'chat.jsx': ['Pill', 'Dot', 'Panel'],
  'pair.jsx': ['Pill', 'Dot', 'StatusPill', 'Panel', 'Field'],
  'notion.jsx': ['Pill', 'Dot', 'Panel'],
  'interests.jsx': ['Pill', 'Dot', 'StatusPill', 'Panel'],
  'caido.jsx': ['Pill', 'Dot', 'Panel'],
  'rag.jsx': ['Pill', 'Dot', 'Panel', 'Field'],
  'app.jsx': ['Rail', 'DashboardMode', 'TraceMode', 'ChatMode', 'PlanMode', 'NotesMode', 'InterestsMode', 'CaidoMode', 'RagMode'],
};

mkdirSync(outDir, { recursive: true });

const body = sources
  .map((name) => {
    const content = readFileSync(resolve(sourceDir, name), 'utf8');
    const aliases = aliasesBySource[name] || [];
    const aliasLine = aliases.length ? `const { ${aliases.join(', ')} } = window;\n` : '';
    return `\n/* ===== ${name} ===== */\n{\n${aliasLine}${content}\n}\n`;
  })
  .join('\n');

writeFileSync(
  outFile,
  `import ReactModule from 'react';\n` +
    `import { createRoot } from 'react-dom/client';\n` +
    `import '../../../../../gui/theme.css';\n\n` +
    `const React = ReactModule;\n` +
    `const ReactDOM = { createRoot };\n` +
    `window.React = React;\n` +
    `window.ReactDOM = ReactDOM;\n` +
    body,
  'utf8',
);
