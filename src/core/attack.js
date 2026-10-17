// MITRE ATT&CK labels for findings (ATT&CK v20, Enterprise). The mapping is a
// pure function of a finding, applied where findings are shown or stored, so
// rule state stays as it was and runs stored before the mapping existed are
// labelled the same way when they are read back (ADR-0017).
//
// Every ID and name was checked against attack.mitre.org. v20 moved "Clear
// Linux or Mac System Logs" from T1070.002 to T1685.006.

/** @typedef {import('../types.js').Finding} Finding */
/** @typedef {{ id: string, name: string }} Technique */

/** The techniques the rules map to, with their tactics. */
export const TECHNIQUES = /** @type {const} */ ({
  'T1110.001': { name: 'Brute Force: Password Guessing', tactics: ['Credential Access'] },
  'T1110.003': { name: 'Brute Force: Password Spraying', tactics: ['Credential Access'] },
  'T1078.003': { name: 'Valid Accounts: Local Accounts', tactics: ['Stealth', 'Persistence', 'Privilege Escalation', 'Initial Access'] },
  'T1021.004': { name: 'Remote Services: SSH', tactics: ['Lateral Movement'] },
  'T1136.001': { name: 'Create Account: Local Account', tactics: ['Persistence'] },
  'T1098.007': { name: 'Account Manipulation: Additional Local or Domain Groups', tactics: ['Persistence', 'Privilege Escalation'] },
  'T1685.006': { name: 'Disable or Modify Tools: Clear Linux or Mac System Logs', tactics: ['Defense Impairment'] },
});

/** @typedef {keyof typeof TECHNIQUES} TechniqueId */

/** @type {Record<Exclude<Finding['rule'], 'account-change'>, TechniqueId[]>} */
const BY_RULE = {
  'brute-force': ['T1110.001'],
  // Guessing, then a login with an account that works.
  'possible-breach': ['T1110.001', 'T1078.003'],
  'unusual-hour': ['T1078.003'],
  'password-spray': ['T1110.003'],
  'distributed-brute-force': ['T1110.001'],
  'new-source': ['T1078.003', 'T1021.004'],
  'log-tampering': ['T1685.006'],
};

/**
 * The ATT&CK techniques a finding is evidence of.
 * @param {Finding} finding
 * @returns {Technique[]}
 */
export function techniquesFor(finding) {
  /** @type {TechniqueId[]} */
  let ids;
  if (finding.rule === 'account-change') {
    ids = [];
    if (finding.created) ids.push('T1136.001');
    if (finding.privilegedGroups.length > 0) ids.push('T1098.007');
  } else {
    ids = BY_RULE[finding.rule] ?? [];
  }
  return ids.map((id) => ({ id, name: TECHNIQUES[id].name }));
}

/**
 * A copy of the finding with its techniques as `attack`.
 * @template {Finding} F
 * @param {F} finding
 * @returns {F & { attack: Technique[] }}
 */
export function withAttack(finding) {
  return { ...finding, attack: techniquesFor(finding) };
}

/** A technique's page on attack.mitre.org. @param {string} id */
export const techniqueUrl = (id) => `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`;
