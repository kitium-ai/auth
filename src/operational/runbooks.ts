export interface RunbookStep {
  title: string;
  description: string;
  command?: string;
}

export interface Runbook {
  name: string;
  scenario: 'backup' | 'restore' | 'rotate-keys' | 'blue-green' | 'incident';
  steps: RunbookStep[];
}

export function defaultRunbooks(): Runbook[] {
  return [
    {
      name: 'Backup storage adapter',
      scenario: 'backup',
      steps: [
        { title: 'Quiesce writes', description: 'Pause mutating traffic or switch to maintenance mode.' },
        { title: 'Snapshot data', description: 'Use adapter native snapshot tooling and verify checksum.' },
        { title: 'Resume service', description: 'Re-enable traffic and confirm health probes.' },
      ],
    },
    {
      name: 'Key rotation',
      scenario: 'rotate-keys',
      steps: [
        { title: 'Generate new key', description: 'Use TokenGovernance.rotateKeys() to emit a new JWKS entry.' },
        { title: 'Publish JWKS', description: 'Expose updated JWKS endpoint to dependents and wait for cache warmup.' },
        { title: 'Revoke old key', description: 'Expire previous key after overlap period.' },
      ],
    },
  ];
}
