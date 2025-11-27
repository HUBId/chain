import type { SloStatus } from '../types';

interface WarningGroup {
  label: string;
  warnings: string[];
}

function collectWarnings(slo?: SloStatus): WarningGroup[] {
  if (!slo) return [];

  const groups: WarningGroup[] = [];
  if (slo.timetoke?.warnings?.length) {
    groups.push({ label: 'Timetoke replay', warnings: slo.timetoke.warnings });
  }
  if (slo.uptime?.warnings?.length) {
    groups.push({ label: 'Uptime accrual', warnings: slo.uptime.warnings });
  }
  return groups;
}

export function SloWarningsCard({ slo }: { slo?: SloStatus }) {
  const groups = collectWarnings(slo);
  if (groups.length === 0) {
    return null;
  }

  return (
    <section className="card slo-warnings" role="alert" aria-live="polite">
      <h2>Service Level Warnings</h2>
      <ul className="warning-list">
        {groups.map((group) => (
          <li key={group.label} className="warning-entry">
            <h3>{group.label}</h3>
            <ul className="warning-chip-list">
              {group.warnings.map((warning, index) => (
                <li key={`${group.label}-${index}`} className="warning-chip">
                  <span aria-hidden="true">⚠️</span>
                  <span>{warning}</span>
                </li>
              ))}
            </ul>
          </li>
        ))}
      </ul>
    </section>
  );
}
