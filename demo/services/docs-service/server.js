const express = require('express');
const cors = require('cors');
const morgan = require('morgan');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

const DOCS_DB = {
  doc1: {
    id: 'doc1',
    title: 'Platform Architecture & Design System',
    classification: 'Internal / Engineering',
    content: 'Zero-Trust Architecture specification and graph-aware authorization topology.',
    lastModified: '2026-09-01'
  },
  wiki: {
    id: 'wiki',
    title: 'Engineering Onboarding Guide',
    classification: 'Public / Internal',
    content: 'Welcome to the team! Setup your dev environment with uv and docker compose.',
    lastModified: '2026-08-15'
  }
};

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'docs-service', port: PORT });
});

app.get('/docs', (req, res) => {
  const subject = req.headers['x-subject'] || 'anonymous';
  res.json({
    service: 'docs-service (Low Sensitivity)',
    caller: subject,
    documents: Object.values(DOCS_DB).map(d => ({ id: d.id, title: d.title, classification: d.classification }))
  });
});

app.get('/docs/:id', (req, res) => {
  const subject = req.headers['x-subject'] || 'anonymous';
  const doc = DOCS_DB[req.params.id];
  if (!doc) {
    return res.status(404).json({ error: 'Document not found' });
  }
  res.json({
    service: 'docs-service',
    caller: subject,
    document: doc
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[docs-service] Running on port ${PORT}`);
});
