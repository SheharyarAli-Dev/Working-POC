import React from 'react';
import { shown } from './types';

// Everything an event carries (paths, argv, addresses, predicates, package text) is untrusted: it comes from the
// package's own behaviour. It is only ever rendered as React text children, which React escapes. It is never set as
// raw HTML, an href, a src or a style, and a long value is cut, with the whole value (still text) in a
// closed "show more" section.
export const TEXT_LIMIT = 160;

// A value as one line of text: strings as they are, anything else as JSON, a missing value as the dash.
export const asText = (value: unknown): string => {
  if (value === null || value === undefined || value === '') return shown(value);
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
};

// The first `limit` characters of a value, for places that cannot hold a "show more" (SVG labels).
export const cut = (value: unknown, limit: number = TEXT_LIMIT): string => {
  const text = asText(value);
  return text.length > limit ? `${text.slice(0, limit)}…` : text;
};

export const SafeText: React.FC<{ value: unknown; limit?: number }> = ({ value, limit = TEXT_LIMIT }) => {
  const text = asText(value);
  if (text.length <= limit) return <>{text}</>;
  return (
    <span className="safe-text-long">
      <span className="safe-text-cut">{text.slice(0, limit)}…</span>{' '}
      <details className="safe-text-more" style={{ display: 'inline' }}>
        <summary>show more ({text.length} characters)</summary>
        <span className="safe-text-full" style={{ wordBreak: 'break-all' }}>{text}</span>
      </details>
    </span>
  );
};

// An address of an event: host:port, a path, or the dash.
export const addressText = (address: any): string => {
  if (!address || typeof address !== 'object') return shown(address);
  if (address.host !== undefined && address.host !== null) return `${asText(address.host)}:${asText(address.port)}`;
  return asText(address.path ?? address);
};
