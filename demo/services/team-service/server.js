const express = require('express');
const cors = require('cors');
const morgan = require('morgan');

const app = express();
const PORT = process.env.PORT || 3002;

app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

const TEAM_DB = {
  eng: {
    id: 'eng',
    name: 'Core Engineering',
    lead: 'user:alice',
    members: ['user:alice', 'user:bob'],
    projects: ['Zero-Trust Gateway', 'Graph Traversal Engine', 'Policy Closed-Loop Feedback'],
    internalSlack: '#eng-private'
  }
};

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'team-service', port: PORT });
});

app.get('/teams/eng', (req, res) => {
  const subject = req.headers['x-subject'] || 'anonymous';
  res.json({
    service: 'team-service (Medium Sensitivity)',
    caller: subject,
    team: TEAM_DB.eng
  });
});

app.get('/teams/eng/members', (req, res) => {
  const subject = req.headers['x-subject'] || 'anonymous';
  res.json({
    service: 'team-service',
    caller: subject,
    team: 'eng',
    members: TEAM_DB.eng.members
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[team-service] Running on port ${PORT}`);
});
