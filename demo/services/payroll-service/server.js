const express = require('express');
const cors = require('cors');
const morgan = require('morgan');

const app = express();
const PORT = process.env.PORT || 3003;

app.use(cors());
app.use(express.json());
app.use(morgan('dev'));

const PAYROLL_DB = {
  summary: {
    period: 'Q3 2026',
    totalDisbursed: '$1,450,000.00',
    executiveBonusPool: '$320,000.00',
    employeeCount: 42,
    confidentiality: 'RESTRICTED - EXECUTIVE & SECURITY ADMIN ONLY'
  },
  records: [
    { employee: 'user:alice', role: 'Staff Engineer', baseSalary: '$210,000', bonus: '$35,000' },
    { employee: 'user:bob', role: 'Junior Engineer', baseSalary: '$135,000', bonus: '$15,000' },
    { employee: 'user:charlie', role: 'Chief Information Security Officer', baseSalary: '$275,000', bonus: '$65,000' }
  ]
};

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'payroll-service', port: PORT });
});

app.get('/payroll/summary', (req, res) => {
  const subject = req.headers['x-subject'] || 'anonymous';
  res.json({
    service: 'payroll-service (HIGH SENSITIVITY)',
    caller: subject,
    data: PAYROLL_DB.summary
  });
});

app.get('/payroll/records', (req, res) => {
  const subject = req.headers['x-subject'] || 'anonymous';
  res.json({
    service: 'payroll-service',
    caller: subject,
    records: PAYROLL_DB.records
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[payroll-service] Running on port ${PORT}`);
});
