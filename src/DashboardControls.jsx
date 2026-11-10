import {useEffect, useRef} from 'react';
import {Command, Link2, Mail, X} from 'lucide-react';

export const agents = [
  {
    name: 'MailAgent', icon: Mail, color: 'cyan', summary: 'Message analysis',
    description: 'Analyzes queued messages, applies rules to set the local verdict, and reports a separate advisory ML prediction when the model is available.',
  },
  {
    name: 'LinkAgent', icon: Link2, color: 'violet', summary: 'Static link checks',
    description: 'Statically scans eligible links from new Gmail imports. Browser observation is disabled for live Gmail links.',
    note: 'Link Lab runs a manual simulation with synthetic behavior and evidence.',
  },
  {
    name: 'ChiefAgent', icon: Command, color: 'gold', summary: 'Decisions and evidence',
    description: 'Records decisions and evidence in the Decision Ledger, correlates supported events, and records local operator overrides.',
  },
];

export function agentStatus(health, runtime) {
  if (health === 'PREVIEW') return 'Demo preview';
  if (health === 'OFFLINE') return 'Offline';
  if (health !== 'OPERATIONAL') return 'Connecting';
  if (runtime === 'processing') return 'Processing';
  return runtime === 'active' ? 'Active' : 'Unavailable';
}

export function formatEvent(event) {
  return String(event.event_type || 'event').replaceAll('_', ' ');
}

function recent(items, limit) {
  return items.sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp)).slice(0, limit);
}

export function collectAlerts(events, ledger, incidents) {
  const emailDecisions = new Map(ledger.filter(item => item.agent === 'MailAgent' && item.email_id != null)
    .map(item => [item.email_id, item]));
  const scans = new Map(ledger.filter(item => item.link_scan).map(item => [item.link_scan.id, item]));
  const unique = new Map();
  for (const event of events) {
    const data = event.data ?? {};
    const entry = scans.get(data.link_scan_id) ?? (event.agent === 'MailAgent' ? emailDecisions.get(data.email_id) : undefined);
    const flagged = ['BLOCK', 'QUARANTINE', 'SUSPICIOUS', 'MALICIOUS', 'FAILED', 'TIMED_OUT'].includes(event.decision);
    const staticFinding = ['medium', 'high'].includes(entry?.link_scan?.severity);
    const critical = event.decision === 'CRITICAL';
    if (!flagged && !staticFinding && !critical) continue;
    const id = JSON.stringify(['event', event.id, event.timestamp]);
    unique.set(id, {
      id, agent: event.agent, title: formatEvent(event), timestamp: event.timestamp,
      decision: staticFinding ? entry.link_scan.severity + ' static severity' : event.decision,
      target: event.target, emailId: data.email_id ?? entry?.email_id,
      ledgerId: entry?.id ?? data.ledger_id,
    });
  }
  for (const item of incidents) {
    if (item.severity !== 'CRITICAL') continue;
    const id = JSON.stringify(['incident', item.id, item.timestamp]);
    unique.set(id, {id, agent: 'ChiefAgent', title: 'Critical incident', timestamp: item.timestamp,
      decision: item.severity, target: item.narrative, incident: true});
  }
  return recent([...unique.values()], 12);
}

export function agentActivity(name, events, ledger, incidents) {
  const activity = events.filter(event => event.agent === name).map(event => ({
    id: 'event-' + event.id, title: formatEvent(event), timestamp: event.timestamp, detail: event.decision,
  }));
  if (name === 'ChiefAgent') {
    activity.push(...ledger.slice(0, 5).map(item => ({
      id: 'ledger-' + item.id, title: 'Recorded ' + item.agent + ' decision', timestamp: item.timestamp, detail: item.decision,
    })));
    activity.push(...incidents.slice(0, 5).map(item => ({
      id: 'incident-' + item.id, title: 'Correlated incident', timestamp: item.timestamp, detail: item.severity,
    })));
  }
  return recent(activity, 5);
}

function Time({value}) {
  const date = new Date(value);
  return <time dateTime={value}>{Number.isFinite(date.getTime()) ? date.toLocaleString() : 'Time unavailable'}</time>;
}

export function DashboardDialog({panel, onClose, alerts, emails, openMessage, openLedger,
                                 health, runtime, events, ledger, incidents}) {
  const dialog = useRef(null);
  const closeButton = useRef(null);
  useEffect(() => {
    const element = dialog.current;
    if (panel && !element.open) {
      element.showModal();
      closeButton.current.focus();
    } else if (!panel && element.open) {
      element.close();
    }
  }, [panel]);

  const notifications = panel === 'notifications';
  const agent = agents.find(item => item.name === panel);
  const status = agent && agentStatus(health, runtime?.[agent.name]);
  const activity = agent ? agentActivity(agent.name, events, ledger, incidents) : [];
  const close = () => {
    dialog.current.close();
    onClose();
  };
  const navigate = (action) => {
    close();
    action();
  };
  return <dialog ref={dialog} onCancel={event => {event.preventDefault(); close();}}
    className="dashboard-dialog" aria-labelledby="dashboard-dialog-title">
    <div className="dashboard-dialog-header">
      <h2 id="dashboard-dialog-title">{notifications ? 'Notifications' : agent?.name}</h2>
      <button ref={closeButton} className="icon-button" type="button" aria-label="Close panel"
        onClick={close}><X size={17}/></button>
    </div>
    {notifications ? alerts.length ? <ul className="dashboard-panel-list">
      {alerts.map(alert => <li key={alert.id}>
        <div className="dashboard-panel-line"><strong>{alert.agent} · {alert.title}</strong><Time value={alert.timestamp}/></div>
        <p>{alert.decision} · {alert.target}</p>
        <div className="dashboard-panel-actions">
          {emails.some(email => email.id === alert.emailId) && <button type="button" className="panel-link"
            onClick={() => navigate(() => openMessage(alert.emailId))}>Open message</button>}
          {!alert.incident && <button type="button" className="panel-link"
            onClick={() => navigate(() => openLedger(alert.ledgerId))}>Open Decision Ledger</button>}
        </div>
      </li>)}
    </ul> : <p className="dashboard-panel-empty">No notifications yet</p> : agent && <>
      <div className="agent-description">
        <p><strong>Runtime status:</strong> {status}</p>
        <p>{agent.description}</p>
        {agent.note && <p>{agent.note}</p>}
      </div>
      <h3 className="dashboard-panel-subtitle">Recent activity</h3>
      {activity.length ? <ul className="dashboard-panel-list">
        {activity.map(item => <li key={item.id}>
          <div className="dashboard-panel-line"><strong>{item.title}</strong><Time value={item.timestamp}/></div>
          <p>{item.detail}</p>
        </li>)}
      </ul> : <p className="dashboard-panel-empty">No recent activity</p>}
    </>}
  </dialog>;
}
