import React, { useState, useEffect, useCallback } from 'react'
import {
  ShieldCheck,
  User,
  Users,
  FileText,
  DollarSign,
  Activity,
  Zap,
  RefreshCw,
  AlertTriangle,
  Navigation,
  Laptop,
  Terminal,
  Layers,
  Server,
  Info,
  CheckCircle2,
  Lock,
  ArrowUpRight,
  TrendingUp,
} from 'lucide-react'

// Personas aligned with SpiceDB relation tuples
interface Persona {
  id: string
  name: string
  subject: string
  role: string
  deviceId: string
  location: { name: string; lat: number; lon: number }
  description: string
  expectedAccess: string[]
}

const PERSONAS: Persona[] = [
  {
    id: 'alice',
    name: 'Alice Cooper',
    subject: 'user:alice',
    role: 'Staff Engineer (Team Lead)',
    deviceId: 'dev_alice_mbp_corp',
    location: { name: 'San Francisco, US', lat: 37.7749, lon: -122.4194 },
    description: 'Member of team:eng. Has view/edit rights to doc1 and team:eng.',
    expectedAccess: ['doc1', 'eng'],
  },
  {
    id: 'bob',
    name: 'Bob Martin',
    subject: 'user:bob',
    role: 'Software Engineer',
    deviceId: 'dev_bob_thinkpad_corp',
    location: { name: 'San Francisco, US', lat: 37.7749, lon: -122.4194 },
    description: 'Member of team:eng. Has view rights to doc1 and team:eng.',
    expectedAccess: ['doc1', 'eng'],
  },
  {
    id: 'charlie',
    name: 'Charlie Davis',
    subject: 'user:charlie',
    role: 'Security Admin',
    deviceId: 'dev_charlie_linux_corp',
    location: { name: 'San Francisco, US', lat: 37.7749, lon: -122.4194 },
    description: 'Member of team:security (admin). Can access high-sensitivity payroll and financials.',
    expectedAccess: ['doc1', 'financials'],
  },
  {
    id: 'mallory',
    name: 'Mallory Vance',
    subject: 'user:mallory',
    role: 'External Contractor (Untrusted)',
    deviceId: 'dev_mallory_unmanaged',
    location: { name: 'Unknown / Remote', lat: 19.076, lon: 72.8777 },
    description: 'External entity with no direct permissions. Blocked by ReBAC graph.',
    expectedAccess: [],
  },
]

interface ServiceTarget {
  id: string
  title: string
  category: string
  sensitivity: 'LOW' | 'MEDIUM' | 'HIGH'
  resourceType: string
  resourceId: string
  defaultPermission: string
  backendPort: number
  icon: React.ComponentType<{ className?: string; size?: number }>
  description: string
}

const SERVICES: ServiceTarget[] = [
  {
    id: 'docs',
    title: 'Documentation Service',
    category: 'Knowledge Base',
    sensitivity: 'LOW',
    resourceType: 'document',
    resourceId: 'doc1',
    defaultPermission: 'view',
    backendPort: 3001,
    icon: FileText,
    description: 'General engineering specs. Perfect fit for Alice, Bob & Charlie.',
  },
  {
    id: 'team',
    title: 'Team Directory Service',
    category: 'Organizational Directory',
    sensitivity: 'MEDIUM',
    resourceType: 'team',
    resourceId: 'eng',
    defaultPermission: 'view',
    backendPort: 3002,
    icon: Users,
    description: 'Internal roster and team assignments. Perfect fit for Engineering members (Alice, Bob).',
  },
  {
    id: 'payroll',
    title: 'Payroll & Compensation',
    category: 'Financial Ledger',
    sensitivity: 'HIGH',
    resourceType: 'document',
    resourceId: 'financials',
    defaultPermission: 'view',
    backendPort: 3003,
    icon: DollarSign,
    description: 'Confidential executive compensation data. Strict Security Admin access (Charlie).',
  },
]

interface FeatureAttribution {
  feature_name: string
  feature_value: number
  shap_value: number
  contribution_score: number
  direction: 'anomalous' | 'benign'
}

interface AuditRecord {
  record_id: string
  session_id: string
  timestamp: number
  decision: {
    action: 'allow' | 'step_up' | 'narrow' | 'deny'
    reason: string
    policy_allowed: boolean
    narrow_applied?: boolean
    challenge_required?: boolean
    trust_score: {
      score: number
      decay_amount: number
      recovery_amount: number
      raw_anomaly_score: number
    }
  }
  feature_vector: {
    behavioral: {
      request_rate_1m: number
      request_rate_5m: number
      geo_velocity_kmh: number
      device_fingerprint_mismatch: number
      time_of_day_deviation: number
    }
    graph: {
      hop_count: number
      path_novelty_score: number
      privilege_shortcut_flag: number
    }
  }
  attributions?: FeatureAttribution[]
  top_anomaly_drivers?: string[]
}

export function App() {
  // Active Persona State
  const [selectedPersona, setSelectedPersona] = useState<Persona>(PERSONAS[0])
  const [sessionId, setSessionId] = useState<string>(`sess_${Date.now()}`)
  const [token, setToken] = useState<string>('')

  // Client Telemetry State
  const [currentDeviceId, setCurrentDeviceId] = useState<string>(PERSONAS[0].deviceId)
  const [currentLat, setCurrentLat] = useState<number>(PERSONAS[0].location.lat)
  const [currentLon, setCurrentLon] = useState<number>(PERSONAS[0].location.lon)
  const [currentLocationName, setCurrentLocationName] = useState<string>(PERSONAS[0].location.name)

  // Current Live Trust State
  const [currentTrustScore, setCurrentTrustScore] = useState<number>(1.0)
  const [lastAction, setLastAction] = useState<string>('allow')
  const [lastReason, setLastReason] = useState<string>('Fresh session initialized with baseline trust.')

  // Request & Response state
  const [activeRequestLoading, setActiveRequestLoading] = useState<string | null>(null)
  const [lastResponse, setLastResponse] = useState<{
    status: number
    action: string
    trustScore: number
    headers: Record<string, string>
    body: any
    timestamp: string
  } | null>(null)

  // Audit records state
  const [auditRecords, setAuditRecords] = useState<AuditRecord[]>([])
  const [isAuditLoading, setIsAuditLoading] = useState<boolean>(false)
  const [isBurstRunning, setIsBurstRunning] = useState<boolean>(false)
  const [isRecoveryRunning, setIsRecoveryRunning] = useState<boolean>(false)

  // 1. Fetch JWT Token for current persona & session
  const fetchToken = useCallback(async (persona: Persona, sessId: string) => {
    try {
      const res = await fetch('/auth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          subject: persona.subject,
          session_id: sessId,
          expires_in_seconds: 86400,
        }),
      })
      if (!res.ok) {
        throw new Error(`Token request failed: ${res.status}`)
      }
      const data = await res.json()
      setToken(data.access_token)
    } catch (err) {
      console.error('Failed to issue JWT token:', err)
    }
  }, [])

  // 2. Fetch Audit Records
  const fetchAuditRecords = useCallback(async () => {
    setIsAuditLoading(true)
    try {
      const res = await fetch('/audit/records?limit=15')
      if (res.ok) {
        const data = await res.json()
        setAuditRecords(data)
      }
    } catch (err) {
      console.error('Failed to fetch audit records:', err)
    } finally {
      setIsAuditLoading(false)
    }
  }, [])

  // Initialize persona selection
  const handleSelectPersona = (p: Persona) => {
    setSelectedPersona(p)
    const newSessId = `sess_${p.id}_${Date.now().toString().slice(-4)}`
    setSessionId(newSessId)
    setCurrentDeviceId(p.deviceId)
    setCurrentLat(p.location.lat)
    setCurrentLon(p.location.lon)
    setCurrentLocationName(p.location.name)
    setCurrentTrustScore(1.0)
    setLastAction('allow')
    setLastReason(`Switched persona to ${p.name}. Baseline trust initialized.`)
    fetchToken(p, newSessId)
  }

  // Initial load
  useEffect(() => {
    fetchToken(selectedPersona, sessionId)
    fetchAuditRecords()
    const interval = setInterval(fetchAuditRecords, 3000)
    return () => clearInterval(interval)
  }, [fetchToken, fetchAuditRecords, selectedPersona, sessionId])

  // 3. Execute Protected Request through Gateway
  const executeGatewayRequest = async (
    resourceType: string,
    resourceId: string,
    permission: string = 'view',
    serviceId: string = 'custom',
    overrideDevice?: string,
    overrideLat?: number,
    overrideLon?: number
  ) => {
    if (!token) {
      await fetchToken(selectedPersona, sessionId)
    }

    setActiveRequestLoading(serviceId)
    try {
      const url = `/api/v1/${resourceType}/${resourceId}?permission=${permission}`
      const headers: Record<string, string> = {
        Authorization: `Bearer ${token}`,
        'X-Device-Id': overrideDevice || currentDeviceId,
        'X-Client-Latitude': (overrideLat ?? currentLat).toString(),
        'X-Client-Longitude': (overrideLon ?? currentLon).toString(),
        'User-Agent': 'ZeroTrustDemoFrontend/1.0',
      }

      const res = await fetch(url, { method: 'GET', headers })
      const body = await res.json().catch(() => ({}))

      const trustHeader = res.headers.get('X-Trust-Score')
      const actionHeader = res.headers.get('X-Decision-Action') || 'deny'
      const auditIdHeader = res.headers.get('X-Audit-Record-Id') || ''
      const narrowAppliedHeader = res.headers.get('X-Narrow-Applied') || 'false'

      const parsedTrust = trustHeader ? parseFloat(trustHeader) : (body.trust_score ?? 0.0)
      setCurrentTrustScore(parsedTrust)
      setLastAction(actionHeader)
      setLastReason(body.detail || body.message || `Action: ${actionHeader}`)

      setLastResponse({
        status: res.status,
        action: actionHeader,
        trustScore: parsedTrust,
        headers: {
          'X-Trust-Score': trustHeader || `${parsedTrust}`,
          'X-Decision-Action': actionHeader,
          'X-Audit-Record-Id': auditIdHeader,
          'X-Narrow-Applied': narrowAppliedHeader,
        },
        body,
        timestamp: new Date().toLocaleTimeString(),
      })

      fetchAuditRecords()
    } catch (err: any) {
      console.error('Request dispatch error:', err)
      setLastResponse({
        status: 500,
        action: 'deny',
        trustScore: 0.0,
        headers: {},
        body: { error: err.message || 'Network error communicating with Gateway' },
        timestamp: new Date().toLocaleTimeString(),
      })
    } finally {
      setActiveRequestLoading(null)
    }
  }

  // 4. Perfect Fit Workflow: Normal Legitimate Activity that Increases / Builds Trust
  const triggerTrustBuildingWorkflow = async () => {
    setIsRecoveryRunning(true)
    // Ensure legitimate telemetry
    setCurrentDeviceId(selectedPersona.deviceId)
    setCurrentLat(selectedPersona.location.lat)
    setCurrentLon(selectedPersona.location.lon)
    setCurrentLocationName(selectedPersona.location.name)

    // Select the primary resource that is a perfect fit for this persona
    const primaryFitResource = selectedPersona.expectedAccess[0] === 'financials'
      ? { type: 'document', id: 'financials' }
      : selectedPersona.expectedAccess[0] === 'eng'
      ? { type: 'team', id: 'eng' }
      : { type: 'document', id: 'doc1' }

    setLastReason(`🌱 Executing authorized benign workflow on ${primaryFitResource.type}:${primaryFitResource.id}. Building trust score...`)

    // Send 3 paced legitimate requests to trigger trust recovery steps
    for (let i = 0; i < 3; i++) {
      await executeGatewayRequest(
        primaryFitResource.type,
        primaryFitResource.id,
        'view',
        'recovery',
        selectedPersona.deviceId,
        selectedPersona.location.lat,
        selectedPersona.location.lon
      )
      await new Promise((r) => setTimeout(r, 400))
    }
    setIsRecoveryRunning(false)
  }

  // 5. MFA Challenge Verification (Step-Up re-authentication)
  const handleVerifyMFAChallenge = async () => {
    try {
      await fetch('/auth/mfa/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          subject: selectedPersona.subject,
          session_id: sessionId,
        }),
      })
    } catch (e) {
      console.error('MFA verify request failed:', e)
    }
    setCurrentTrustScore(1.0)
    setLastAction('allow')
    setLastReason('✅ Multi-Factor Authentication verified. Quarantine restrictions lifted and session trust restored to 1.00.')
    fetchToken(selectedPersona, sessionId)
  }

  // 6. Anomaly Simulator: Rapid Request Burst
  const triggerRapidBurst = async () => {
    setIsBurstRunning(true)
    setLastReason('⚡ Rapid burst simulation triggered: Firing 20 requests in 400ms...')
    for (let i = 0; i < 20; i++) {
      await executeGatewayRequest('document', 'doc1', 'view', 'burst')
      await new Promise((r) => setTimeout(r, 20))
    }
    setIsBurstRunning(false)
  }

  // 7. Anomaly Simulator: Impossible Travel (Teleport to Tokyo)
  const triggerImpossibleTravel = async () => {
    const tokyoLat = 35.6762
    const tokyoLon = 139.6503
    setCurrentLat(tokyoLat)
    setCurrentLon(tokyoLon)
    setCurrentLocationName('Tokyo, JP (Teleported)')
    setLastReason('✈️ Impossible travel simulated: Instant geo-jump from SF to Tokyo (~8,200 km).')

    setTimeout(() => {
      executeGatewayRequest('document', 'doc1', 'view', 'travel', currentDeviceId, tokyoLat, tokyoLon)
    }, 100)
  }

  // 8. Anomaly Simulator: Untrusted / Rogue Device Spoofing
  const triggerDeviceSpoofing = async () => {
    const spoofedId = 'unknown_rogue_device_attacker'
    setCurrentDeviceId(spoofedId)
    setLastReason('🕵️ Device mismatch triggered: Injected unrecognized hardware fingerprint.')
    setTimeout(() => {
      executeGatewayRequest('document', 'doc1', 'view', 'device', spoofedId)
    }, 100)
  }

  // 9. Reset baseline
  const handleResetBaseline = () => {
    const freshSess = `sess_${selectedPersona.id}_${Date.now().toString().slice(-4)}`
    setSessionId(freshSess)
    setCurrentDeviceId(selectedPersona.deviceId)
    setCurrentLat(selectedPersona.location.lat)
    setCurrentLon(selectedPersona.location.lon)
    setCurrentLocationName(selectedPersona.location.name)
    setCurrentTrustScore(1.0)
    setLastAction('allow')
    setLastReason('Baseline state restored. Session refreshed.')
    setLastResponse(null)
    fetchToken(selectedPersona, freshSess)
  }

  // Helper for trust score colors
  const getActionColor = (action: string) => {
    switch (action.toLowerCase()) {
      case 'allow':
        return '#10b981'
      case 'step_up':
        return '#f59e0b'
      case 'narrow':
        return '#ef4444'
      case 'deny':
      default:
        return '#b91c1c'
    }
  }

  const getActionBadgeClass = (action: string) => {
    switch (action.toLowerCase()) {
      case 'allow':
        return 'tag tag-allow'
      case 'step_up':
        return 'tag tag-step_up'
      case 'narrow':
        return 'tag tag-narrow'
      case 'deny':
      default:
        return 'tag tag-deny'
    }
  }

  const formatScore = (num: number) => (isNaN(num) ? '0.00' : num.toFixed(2))

  return (
    <div className="container">
      {/* Header */}
      <header>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ padding: '8px', background: 'rgba(59, 130, 246, 0.2)', borderRadius: '10px' }}>
            <ShieldCheck size={28} color="#60a5fa" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h1 style={{ fontSize: '20px', fontWeight: 800, letterSpacing: '-0.02em' }}>
                Zero-Trust API Gateway
              </h1>
              <span className="brand-badge">Closed-Loop ReBAC Testbed</span>
            </div>
            <p style={{ fontSize: '13px', color: '#94a3b8', marginTop: '2px' }}>
              Dynamic trust decay, graph-aware relationship authorization & real-time SHAP explainability
            </p>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', color: '#10b981' }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#10b981', display: 'inline-block' }} />
            Gateway Online :8000
          </div>
          <button className="btn btn-secondary" onClick={handleResetBaseline} title="Reset Baseline Session">
            <RefreshCw size={14} />
            Reset State
          </button>
        </div>
      </header>

      {/* 3-Column Layout */}
      <div className="grid-3">
        {/* Left Column: Persona, Telemetry & Anomaly Lab */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Persona Card */}
          <div className="card">
            <div className="card-title">
              <User size={18} color="#60a5fa" />
              <span>Active Persona</span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '16px' }}>
              {PERSONAS.map((p) => {
                const isActive = selectedPersona.id === p.id
                return (
                  <button
                    key={p.id}
                    onClick={() => handleSelectPersona(p)}
                    className={`persona-btn ${isActive ? 'active' : ''}`}
                    style={{ justifyContent: 'space-between', textAlign: 'left' }}
                  >
                    <div>
                      <div style={{ fontWeight: 600, color: isActive ? '#60a5fa' : '#f8fafc' }}>
                        {p.name}
                      </div>
                      <div style={{ fontSize: '11px', color: '#94a3b8' }}>{p.role}</div>
                    </div>
                    <span style={{ fontSize: '10px', opacity: 0.8 }}>{p.subject}</span>
                  </button>
                )
              })}
            </div>

            <div style={{ background: '#0b0f19', padding: '10px', borderRadius: '6px', fontSize: '12px', color: '#94a3b8' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '4px', marginBottom: '4px', color: '#cbd5e1' }}>
                <Info size={13} />
                <span>Persona Entitlements:</span>
              </div>
              <p style={{ lineHeight: 1.4 }}>{selectedPersona.description}</p>
            </div>
          </div>

          {/* Telemetry & Context */}
          <div className="card">
            <div className="card-title">
              <Laptop size={18} color="#a78bfa" />
              <span>Client Telemetry & Context</span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '12px' }}>
              <div>
                <span style={{ color: '#94a3b8', display: 'block', marginBottom: '2px' }}>Session Token:</span>
                <code style={{ fontSize: '11px', color: '#38bdf8', wordBreak: 'break-all' }}>
                  {sessionId}
                </code>
              </div>

              <div>
                <span style={{ color: '#94a3b8', display: 'block', marginBottom: '2px' }}>Device Fingerprint:</span>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Laptop size={14} color="#94a3b8" />
                  <code style={{ fontSize: '11px', color: currentDeviceId.includes('rogue') ? '#ef4444' : '#e2e8f0' }}>
                    {currentDeviceId}
                  </code>
                </div>
              </div>

              <div>
                <span style={{ color: '#94a3b8', display: 'block', marginBottom: '2px' }}>Geo Location:</span>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Navigation size={14} color="#94a3b8" />
                  <span style={{ color: currentLocationName.includes('Tokyo') ? '#ef4444' : '#e2e8f0' }}>
                    {currentLocationName} ({currentLat.toFixed(2)}, {currentLon.toFixed(2)})
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Threat & Anomaly Injection Lab */}
          <div className="card" style={{ border: '1px solid rgba(239, 68, 68, 0.3)' }}>
            <div className="card-title" style={{ color: '#f87171' }}>
              <Zap size={18} color="#ef4444" />
              <span>Anomaly Injection Lab</span>
            </div>
            <p style={{ fontSize: '12px', color: '#94a3b8', marginBottom: '12px' }}>
              Simulate real-time malicious signals to test the Isolation Forest trust decay & closed-loop feedback:
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <button
                className="btn btn-warning"
                onClick={triggerRapidBurst}
                disabled={isBurstRunning}
                style={{ width: '100%', justifyContent: 'center' }}
              >
                <Activity size={15} />
                {isBurstRunning ? 'Firing 20 Reqs...' : 'Trigger Rapid Request Burst (20 reqs)'}
              </button>

              <button
                className="btn btn-danger"
                onClick={triggerImpossibleTravel}
                style={{ width: '100%', justifyContent: 'center' }}
              >
                <Navigation size={15} />
                Simulate Impossible Travel (SF → Tokyo)
              </button>

              <button
                className="btn btn-secondary"
                onClick={triggerDeviceSpoofing}
                style={{ width: '100%', justifyContent: 'center', border: '1px solid #ef4444' }}
              >
                <AlertTriangle size={15} color="#ef4444" />
                Inject Rogue Device Fingerprint
              </button>
            </div>
          </div>
        </div>

        {/* Center Column: Live Trust Meter, Microservices & Response Inspector */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Trust Meter Gauge Card */}
          <div className="card" style={{ background: 'linear-gradient(180deg, #1e293b 0%, #0f172a 100%)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div className="card-title" style={{ marginBottom: 0 }}>
                <Activity size={18} color="#38bdf8" />
                <span>Continuous Trust Score</span>
              </div>
              <span className={getActionBadgeClass(lastAction)}>
                Action: {lastAction.toUpperCase()}
              </span>
            </div>

            <div className="score-gauge">
              <div className="score-number" style={{ color: getActionColor(lastAction) }}>
                {formatScore(currentTrustScore)}
              </div>
              <div style={{ fontSize: '12px', color: '#94a3b8', marginTop: '-4px' }}>
                Trust Level ({lastAction === 'allow' ? 'Standard Access' : lastAction === 'step_up' ? 'MFA Required' : lastAction === 'narrow' ? 'Graph Narrowed' : 'Terminated'})
              </div>

              {/* Progress Bar */}
              <div className="score-bar-bg">
                <div
                  className="score-bar-fill"
                  style={{
                    width: `${Math.max(0, Math.min(100, currentTrustScore * 100))}%`,
                    backgroundColor: getActionColor(lastAction),
                  }}
                />
              </div>

              {/* Trust Score Bands */}
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: '#64748b' }}>
                <span>0.00 (DENY)</span>
                <span>0.35 (NARROW)</span>
                <span>0.60 (STEP-UP)</span>
                <span>0.80 (ALLOW)</span>
                <span>1.00</span>
              </div>
            </div>

            <div style={{ background: 'rgba(15, 23, 42, 0.8)', padding: '10px 14px', borderRadius: '8px', fontSize: '12px' }}>
              <div style={{ fontWeight: 600, color: '#cbd5e1', marginBottom: '2px' }}>Decision Rationale:</div>
              <p style={{ color: '#94a3b8', margin: 0 }}>{lastReason}</p>
            </div>

            {/* Quick Recovery / Step-Up MFA Button if degraded or quarantined */}
            {(lastAction === 'step_up' || lastAction === 'narrow' || lastAction === 'deny' || currentTrustScore < 0.75) && (
              <div style={{ marginTop: '12px', paddingTop: '12px', borderTop: '1px solid #334155' }}>
                <button
                  className="btn btn-warning"
                  onClick={handleVerifyMFAChallenge}
                  style={{ width: '100%', justifyContent: 'center' }}
                >
                  <Lock size={15} />
                  {lastAction === 'step_up'
                    ? 'Complete MFA Verification (Restore Trust to 1.00)'
                    : lastAction === 'narrow'
                    ? 'Unlock Quarantine via MFA Verification (Restore Graph Access)'
                    : lastAction === 'deny'
                    ? 'Emergency Re-Auth via MFA (Lift Restrictions & Reset Trust)'
                    : 'Verify MFA (Restore Session Trust to 1.00)'}
                </button>
              </div>
            )}

          </div>

          {/* Trust Builder & Benign Activity Card */}
          <div className="card" style={{ border: '1px solid rgba(16, 185, 129, 0.4)', background: 'rgba(16, 185, 129, 0.05)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <div className="card-title" style={{ color: '#34d399', marginBottom: 0 }}>
                <TrendingUp size={18} color="#10b981" />
                <span>Legitimate Authorized Activity (Trust Builder)</span>
              </div>
              <span className="tag tag-allow">Trust Recovery</span>
            </div>
            <p style={{ fontSize: '12px', color: '#94a3b8', marginBottom: '12px' }}>
              Execute legitimate, authorized actions aligned with <strong>{selectedPersona.name}</strong>'s role and matching device to build and increase trust score:
            </p>
            <button
              className="btn btn-success"
              onClick={triggerTrustBuildingWorkflow}
              disabled={isRecoveryRunning || selectedPersona.id === 'mallory'}
              style={{ width: '100%', justifyContent: 'center' }}
            >
              <CheckCircle2 size={16} />
              {isRecoveryRunning
                ? 'Executing Authorized Requests & Recovering Score...'
                : `Run Authorized Workflow as ${selectedPersona.name} (Increases Trust)`}
            </button>
          </div>

          {/* Microservices Routing Gate */}
          <div className="card">
            <div className="card-title">
              <Server size={18} color="#60a5fa" />
              <span>Microservices Behind Gateway</span>
            </div>
            <p style={{ fontSize: '12px', color: '#94a3b8', marginBottom: '14px' }}>
              All requests are evaluated against the SpiceDB ReBAC graph + Isolation Forest trust score before proxying:
            </p>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {SERVICES.map((svc) => {
                const SvcIcon = svc.icon
                const isExecuting = activeRequestLoading === svc.id
                const isPerfectFit = selectedPersona.expectedAccess.includes(svc.resourceId)

                return (
                  <div
                    key={svc.id}
                    className="service-card"
                    style={{
                      border: isPerfectFit ? '1px solid rgba(16, 185, 129, 0.4)' : undefined,
                      background: isPerfectFit ? 'rgba(16, 185, 129, 0.03)' : undefined,
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <div style={{ padding: '6px', background: isPerfectFit ? 'rgba(16, 185, 129, 0.2)' : 'rgba(59, 130, 246, 0.15)', borderRadius: '6px' }}>
                          <SvcIcon size={20} />
                        </div>
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <div style={{ fontWeight: 600, fontSize: '14px', color: '#f8fafc' }}>
                              {svc.title}
                            </div>
                            {isPerfectFit && (
                              <span style={{ fontSize: '10px', background: 'rgba(16, 185, 129, 0.2)', color: '#34d399', padding: '1px 5px', borderRadius: '3px', fontWeight: 700 }}>
                                ⭐ PERFECT FIT
                              </span>
                            )}
                          </div>
                          <div style={{ fontSize: '11px', color: '#94a3b8' }}>
                            Target: <code style={{ color: '#38bdf8' }}>/api/v1/{svc.resourceType}/{svc.resourceId}</code>
                          </div>
                        </div>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <span
                          style={{
                            fontSize: '10px',
                            fontWeight: 700,
                            padding: '2px 6px',
                            borderRadius: '4px',
                            backgroundColor:
                              svc.sensitivity === 'LOW'
                                ? 'rgba(16, 185, 129, 0.15)'
                                : svc.sensitivity === 'MEDIUM'
                                ? 'rgba(245, 158, 11, 0.15)'
                                : 'rgba(239, 68, 68, 0.15)',
                            color:
                              svc.sensitivity === 'LOW'
                                ? '#34d399'
                                : svc.sensitivity === 'MEDIUM'
                                ? '#fbbf24'
                                : '#f87171',
                          }}
                        >
                          {svc.sensitivity} SENSITIVITY
                        </span>
                      </div>
                    </div>

                    <p style={{ fontSize: '11px', color: '#94a3b8', marginBottom: '10px' }}>
                      {svc.description}
                    </p>

                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '11px', color: '#64748b' }}>
                        Backend: <code style={{ color: '#cbd5e1' }}>localhost:{svc.backendPort}</code>
                      </span>
                      <button
                        className={`btn ${isPerfectFit ? 'btn-success' : ''}`}
                        onClick={() => executeGatewayRequest(svc.resourceType, svc.resourceId, svc.defaultPermission, svc.id)}
                        disabled={isExecuting}
                      >
                        <ArrowUpRight size={14} />
                        {isExecuting ? 'Evaluating...' : isPerfectFit ? 'Invoke (Builds Trust)' : 'Invoke via Gateway'}
                      </button>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Response Inspector */}
          <div className="card">
            <div className="card-title">
              <Terminal size={18} color="#38bdf8" />
              <span>Gateway Response Inspector</span>
            </div>

            {lastResponse ? (
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '10px' }}>
                  <span
                    className="tag"
                    style={{
                      background: lastResponse.status === 200 ? 'rgba(16, 185, 129, 0.2)' : 'rgba(239, 68, 68, 0.2)',
                      color: lastResponse.status === 200 ? '#34d399' : '#f87171',
                    }}
                  >
                    HTTP {lastResponse.status}
                  </span>
                  <span className={getActionBadgeClass(lastResponse.action)}>
                    {lastResponse.action.toUpperCase()}
                  </span>
                  <span style={{ fontSize: '11px', color: '#64748b' }}>{lastResponse.timestamp}</span>
                </div>

                <div className="response-box">
                  {JSON.stringify(
                    {
                      headers: lastResponse.headers,
                      response_payload: lastResponse.body,
                    },
                    null,
                    2
                  )}
                </div>
              </div>
            ) : (
              <div style={{ textAlign: 'center', padding: '24px 0', color: '#64748b', fontSize: '13px' }}>
                Select a service above to dispatch an authorized request through the Gateway.
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Live Audit Feed & SHAP Explainability Stream */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div className="card" style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
              <div className="card-title" style={{ marginBottom: 0 }}>
                <Layers size={18} color="#a78bfa" />
                <span>Live Audit & SHAP Attributions</span>
              </div>
              <button
                className="btn btn-secondary"
                onClick={fetchAuditRecords}
                disabled={isAuditLoading}
                style={{ padding: '4px 8px', fontSize: '11px' }}
              >
                <RefreshCw size={12} />
                Refresh
              </button>
            </div>

            <p style={{ fontSize: '12px', color: '#94a3b8', marginBottom: '12px' }}>
              Real-time feed of gateway evaluations with feature-level SHAP anomaly attributions:
            </p>

            <div className="audit-feed" style={{ flex: 1 }}>
              {auditRecords.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '30px 0', color: '#64748b', fontSize: '13px' }}>
                  No audit records captured yet. Send requests to populate.
                </div>
              ) : (
                auditRecords.map((rec) => {
                  const action = rec.decision.action
                  return (
                    <div key={rec.record_id} className="audit-item">
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                        <span className={getActionBadgeClass(action)}>
                          {action.toUpperCase()}
                        </span>
                        <span style={{ fontSize: '10px', color: '#64748b' }}>
                          {new Date(rec.timestamp * 1000).toLocaleTimeString()}
                        </span>
                      </div>

                      <div style={{ fontSize: '12px', marginBottom: '6px' }}>
                        <span style={{ color: '#38bdf8', fontWeight: 600 }}>{rec.session_id}</span>
                        <div style={{ color: '#cbd5e1', marginTop: '2px', fontSize: '11px' }}>
                          {rec.decision.reason}
                        </div>
                      </div>

                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: '#94a3b8', marginBottom: '8px' }}>
                        <span>Trust Score: <strong style={{ color: getActionColor(action) }}>{formatScore(rec.decision.trust_score.score)}</strong></span>
                        {rec.decision.trust_score.decay_amount > 0 && (
                          <span style={{ color: '#ef4444' }}>
                            Decay: -{formatScore(rec.decision.trust_score.decay_amount)}
                          </span>
                        )}
                        {rec.decision.trust_score.recovery_amount > 0 && (
                          <span style={{ color: '#10b981' }}>
                            Recovery: +{formatScore(rec.decision.trust_score.recovery_amount)}
                          </span>
                        )}
                      </div>

                      {/* SHAP Attributions */}
                      {rec.attributions && rec.attributions.length > 0 && (
                        <div style={{ borderTop: '1px solid #1e293b', paddingTop: '8px', marginTop: '4px' }}>
                          <div style={{ fontSize: '10px', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase', marginBottom: '4px' }}>
                            Top Feature Drivers (SHAP)
                          </div>
                          {rec.attributions.slice(0, 3).map((attr) => (
                            <div key={attr.feature_name} className="shap-bar">
                              <span className="shap-label" title={attr.feature_name}>
                                {attr.feature_name.replace(/_/g, ' ')}
                              </span>
                              <div className="shap-track">
                                <div
                                  className={attr.direction === 'anomalous' ? 'shap-fill-anomalous' : 'shap-fill-benign'}
                                  style={{ width: `${Math.max(10, Math.min(100, attr.contribution_score * 100))}%` }}
                                />
                              </div>
                              <span style={{ fontSize: '10px', color: attr.direction === 'anomalous' ? '#ef4444' : '#10b981', width: '38px', textAlign: 'right' }}>
                                {attr.direction === 'anomalous' ? '▲ threat' : '● normal'}
                              </span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )
                })
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default App
