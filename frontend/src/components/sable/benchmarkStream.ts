export interface SableBenchmarkProgress {
  scenario: string;
  pct: number;
}

export async function executeSableBenchmark(
  onProgress: (progress: SableBenchmarkProgress) => void,
): Promise<any> {
  const response = await fetch('/api/sable/benchmark/run', { method: 'POST' });
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new Error(body?.detail ?? `Benchmark could not start (HTTP ${response.status}).`);
  }
  if (!response.body) throw new Error('Benchmark response did not include a progress stream.');

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffered = '';
  let result: any = null;

  const consumeLine = (line: string) => {
    if (!line.startsWith('data:')) return;
    let event: any;
    try {
      event = JSON.parse(line.slice(5).trim());
    } catch {
      throw new Error('Benchmark returned an invalid progress event.');
    }
    if (event.type === 'benchmark.progress') {
      onProgress({ scenario: event.payload.scenario, pct: event.payload.pct });
    } else if (event.type === 'benchmark.complete') {
      result = event.payload;
    } else if (event.type === 'benchmark.error') {
      throw new Error(event.payload?.error ?? 'Benchmark failed.');
    }
  };

  while (true) {
    const { done, value } = await reader.read();
    buffered += done ? decoder.decode() : decoder.decode(value, { stream: true });
    const lines = buffered.split(/\r?\n/);
    buffered = lines.pop() ?? '';
    for (const line of lines) consumeLine(line);
    if (done) break;
  }
  if (buffered.trim()) consumeLine(buffered);
  if (!result) throw new Error('Benchmark stream ended without a completed result.');
  return result;
}
