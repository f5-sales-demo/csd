const ALERT_NAMES = new Set(['ClientSideDefenseHttpHeaderCompromised', 'ClientSideDefenseHttpHeaderModified']);

const object = (value) => value && typeof value === 'object' && !Array.isArray(value);

function parseJsonString(value) {
  if (typeof value !== 'string') return value;
  const text = value.trim();
  if (!text.startsWith('{') && !text.startsWith('[')) return value;
  try {
    return JSON.parse(text);
  } catch {
    return value;
  }
}

export function flattenAlertPayload(payload) {
  const results = [];
  const visit = (input) => {
    const value = parseJsonString(input);
    if (Array.isArray(value)) {
      value.forEach(visit);
      return;
    }
    if (!object(value)) return;
    const labels = object(value.labels) ? value.labels : {};
    const alertname = value.alertname ?? labels.alertname ?? value.name;
    if (ALERT_NAMES.has(alertname)) results.push(value);
    for (const [key, child] of Object.entries(value)) {
      if (['labels', 'annotations'].includes(key)) continue;
      if (Array.isArray(child) || object(child) || typeof child === 'string') visit(child);
    }
  };
  visit(payload);
  return results;
}

const text = (value) => (typeof value === 'string' ? value : '');
const lower = (value) => text(value).toLowerCase();

function fields(alert) {
  const labels = object(alert.labels) ? alert.labels : {};
  const annotations = object(alert.annotations) ? alert.annotations : {};
  return {
    alertname: alert.alertname ?? labels.alertname ?? alert.name,
    namespace: alert.namespace ?? labels.namespace,
    path: alert.path ?? labels.path ?? labels.url_path ?? annotations.path,
    header: labels.header ?? alert.header,
    startsAt: alert.startsAt ?? alert.starts_at ?? alert.start_time,
    endsAt: alert.endsAt ?? alert.ends_at ?? alert.end_time,
    modification: alert.modification ?? labels.modification ?? annotations.modification,
    displayName: alert.display_name ?? alert.displayName ?? annotations.display_name ?? annotations.summary,
    description: alert.description ?? annotations.description,
    state: alert.state ?? alert.status ?? (alert.endsAt || alert.ends_at ? 'resolved' : 'firing'),
  };
}

function includesHeader(value, headerId) {
  if (Array.isArray(value)) return value.some((item) => includesHeader(item, headerId));
  return lower(value)
    .split(/[,;\s]+/)
    .filter(Boolean)
    .includes(headerId.toLowerCase());
}

function safeText(value, limit = 500) {
  return text(value)
    .replace(/[\r\n\t]+/g, ' ')
    .trim()
    .slice(0, limit);
}

export function correlateAlert(alert, expected, { current = false, allowPriorResolution = false } = {}) {
  const item = fields(alert);
  const started = Date.parse(item.startsAt);
  const windowStart = Date.parse(expected.windowStart);
  const windowEnd = Date.parse(expected.windowEnd);
  const state = lower(item.state) === 'resolved' || item.endsAt ? 'resolved' : 'firing';
  if (!ALERT_NAMES.has(item.alertname)) return null;
  if (item.namespace !== expected.namespace) return null;
  if (item.path !== expected.path) return null;
  if (!includesHeader(item.header, expected.headerId)) return null;
  if (!Number.isFinite(started) || started > windowEnd) return null;
  if (started < windowStart && !(current && state === 'firing') && !(allowPriorResolution && state === 'resolved'))
    return null;
  return {
    alert_name: item.alertname,
    namespace: item.namespace,
    path: item.path,
    header_id: expected.headerId,
    state,
    starts_at: new Date(started).toISOString(),
    ends_at: Number.isFinite(Date.parse(item.endsAt)) ? new Date(item.endsAt).toISOString() : null,
    modification: safeText(item.modification, 80) || null,
    display_name: safeText(item.displayName, 160) || null,
    description: safeText(item.description) || null,
  };
}

function dedupeAlerts(matches) {
  const deduped = new Map();
  for (const alert of matches) {
    const key = [
      alert.alert_name,
      alert.namespace,
      alert.path,
      alert.header_id,
      alert.starts_at,
      alert.state,
      alert.ends_at || '',
    ].join('|');
    if (!deduped.has(key)) deduped.set(key, alert);
  }
  return [...deduped.values()].sort((a, b) => a.starts_at.localeCompare(b.starts_at));
}

export function correlateAlerts(payloads, expected, options = {}) {
  return dedupeAlerts(
    payloads
      .flatMap(flattenAlertPayload)
      .map((alert) => correlateAlert(alert, expected, options))
      .filter(Boolean),
  );
}

export function correlateAlertViews(views, expected, options = {}) {
  const normalizeView = (view) => (view == null ? [] : Array.isArray(view) ? view : [view]);
  const current = correlateAlerts(normalizeView(views?.current), expected, { current: true });
  const history = correlateAlerts(normalizeView(views?.history), expected, {
    allowPriorResolution: options.allowPriorResolution === true,
  });
  return dedupeAlerts([...current, ...history]);
}

export function classifyAlerts(matches, telemetryValid = true) {
  if (!telemetryValid) return 'INVALID_TEST';
  if (matches.some(({ alert_name }) => alert_name === 'ClientSideDefenseHttpHeaderCompromised')) return 'COMPROMISED';
  if (matches.some(({ alert_name }) => alert_name === 'ClientSideDefenseHttpHeaderModified')) return 'MODIFIED_ONLY';
  return 'NO_ALERT_WITHIN_WINDOW';
}
