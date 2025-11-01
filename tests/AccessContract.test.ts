import { describe, it, expect, beforeEach } from "vitest";
import { stringAsciiCV, uintCV, optionalCV, principalCV, noneCV } from "@stacks/transactions";

const ERR_NOT_OWNER = 301;
const ERR_INVALID_GRANT_TYPE = 303;
const ERR_INVALID_EXPIRY = 304;
const ERR_GRANT_ALREADY_EXISTS = 305;
const ERR_GRANT_NOT_FOUND = 306;
const ERR_INVALID_REASON_LENGTH = 307;
const ERR_MAX_GRANTS_EXCEEDED = 308;
const ERR_NOT_REGISTERED = 300;
const ERR_INVALID_ACCESS_LEVEL = 312;
const ERR_GROUP_NOT_FOUND = 313;
const ERR_INDIVIDUAL = "individual";
const ERR_GROUP = "group";
const ERR_TEMPORARY = "temporary";

interface Grant {
  grantType: string;
  expiry: number | null;
  reason: string;
  level: number;
  grantedAt: number;
  granter: string;
  revoked: boolean;
}

interface Group {
  name: string;
  creator: string;
  active: boolean;
}

interface AuditLog {
  action: string;
  actor: string;
  recordId: number;
  timestamp: number;
  details: string;
}

interface Result<T> {
  ok: boolean;
  value: T;
}

class AccessContractMock {
  state: {
    nextGrantId: number;
    maxGrantsPerRecord: number;
    auditEnabled: boolean;
    recordOwners: Map<number, string>;
    accessGrants: Map<string, Grant>;
    recordGrantCounts: Map<number, number>;
    groupMembers: Map<string, boolean>;
    groups: Map<number, Group>;
    auditLogs: Map<number, AuditLog>;
    nextAuditId: number;
  } = {
    nextGrantId: 0,
    maxGrantsPerRecord: 50,
    auditEnabled: true,
    recordOwners: new Map(),
    accessGrants: new Map(),
    recordGrantCounts: new Map(),
    groupMembers: new Map(),
    groups: new Map(),
    auditLogs: new Map(),
    nextAuditId: 0,
  };
  blockHeight: number = 0;
  caller: string = "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM";

  constructor() {
    this.reset();
  }

  reset() {
    this.state = {
      nextGrantId: 0,
      maxGrantsPerRecord: 50,
      auditEnabled: true,
      recordOwners: new Map(),
      accessGrants: new Map(),
      recordGrantCounts: new Map(),
      groupMembers: new Map(),
      groups: new Map(),
      auditLogs: new Map(),
      nextAuditId: 0,
    };
    this.blockHeight = 0;
    this.caller = "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM";
  }

  setRecordOwner(recordId: number): Result<boolean> {
    if (this.state.recordOwners.has(recordId)) {
      return { ok: false, value: false };
    }
    this.state.recordOwners.set(recordId, this.caller);
    this.logAudit("owner-set", recordId, `Owner set for record ${recordId}`);
    return { ok: true, value: true };
  }

  grantAccess(
    recordId: number,
    grantee: string,
    grantType: string,
    expiry: number | null,
    reason: string,
    level: number
  ): Result<boolean> {
    const owner = this.state.recordOwners.get(recordId);
    if (!owner || owner !== this.caller) {
      return { ok: false, value: false };
    }
    const count = this.state.recordGrantCounts.get(recordId) || 0;
    const key = `${recordId}-${grantee}`;
    if (count >= this.state.maxGrantsPerRecord) {
      return { ok: false, value: false };
    }
    if (this.state.accessGrants.has(key)) {
      return { ok: false, value: false };
    }
    if (!["individual", "group", "temporary"].includes(grantType)) {
      return { ok: false, value: false };
    }
    if (expiry !== null && expiry < this.blockHeight) {
      return { ok: false, value: false };
    }
    if (reason.length === 0 || reason.length > 200) {
      return { ok: false, value: false };
    }
    if (level > 3) {
      return { ok: false, value: false };
    }
    this.state.accessGrants.set(key, {
      grantType,
      expiry,
      reason,
      level,
      grantedAt: this.blockHeight,
      granter: this.caller,
      revoked: false,
    });
    this.state.recordGrantCounts.set(recordId, count + 1);
    this.logAudit("access-granted", recordId, `Granted to ${grantee}`);
    return { ok: true, value: true };
  }

  revokeAccess(recordId: number, grantee: string): Result<boolean> {
    const owner = this.state.recordOwners.get(recordId);
    if (!owner || owner !== this.caller) {
      return { ok: false, value: false };
    }
    const key = `${recordId}-${grantee}`;
    const grant = this.state.accessGrants.get(key);
    if (!grant || grant.revoked) {
      return { ok: false, value: false };
    }
    this.state.accessGrants.set(key, { ...grant, revoked: true });
    this.logAudit("access-revoked", recordId, `Revoked for ${grantee}`);
    return { ok: true, value: true };
  }

  createGroup(groupName: string): Result<number> {
    if (groupName.length === 0 || groupName.length > 50) {
      return { ok: false, value: 0 };
    }
    const id = this.state.nextGrantId;
    if (this.state.groups.has(id)) {
      return { ok: false, value: 0 };
    }
    this.state.groups.set(id, {
      name: groupName,
      creator: this.caller,
      active: true,
    });
    this.state.nextGrantId++;
    this.logAudit("group-created", 0, `Group ${groupName}`);
    return { ok: true, value: id };
  }

  addGroupMember(groupId: number, member: string): Result<boolean> {
    const group = this.state.groups.get(groupId);
    if (!group || group.creator !== this.caller) {
      return { ok: false, value: false };
    }
    if (!group.active) {
      return { ok: false, value: false };
    }
    const key = `${groupId}-${member}`;
    this.state.groupMembers.set(key, true);
    this.logAudit("member-added", 0, `Added to group ${groupId}`);
    return { ok: true, value: true };
  }

  grantGroupAccess(
    recordId: number,
    groupId: number,
    expiry: number | null,
    reason: string,
    level: number
  ): Result<boolean> {
    const owner = this.state.recordOwners.get(recordId);
    if (!owner || owner !== this.caller) {
      return { ok: false, value: false };
    }
    const group = this.state.groups.get(groupId);
    if (!group) {
      return { ok: false, value: false };
    }
    if (expiry !== null && expiry < this.blockHeight) {
      return { ok: false, value: false };
    }
    if (reason.length === 0 || reason.length > 200) {
      return { ok: false, value: false };
    }
    if (level > 3) {
      return { ok: false, value: false };
    }
    const proxyKey = `${recordId}-${group.creator}`;
    if (this.state.accessGrants.has(proxyKey)) {
      return { ok: false, value: false };
    }
    this.state.accessGrants.set(proxyKey, {
      grantType: "group",
      expiry,
      reason,
      level,
      grantedAt: this.blockHeight,
      granter: this.caller,
      revoked: false,
    });
    this.logAudit("group-access-granted", recordId, `Group ${groupId}`);
    return { ok: true, value: true };
  }

  setMaxGrants(newMax: number): Result<boolean> {
    const owner = this.state.recordOwners.get(0);
    if (!owner || owner !== this.caller) {
      return { ok: false, value: false };
    }
    if (newMax <= 0) {
      return { ok: false, value: false };
    }
    this.state.maxGrantsPerRecord = newMax;
    this.logAudit("config-updated", 0, "Max grants updated");
    return { ok: true, value: true };
  }

  toggleAudit(enabled: boolean): Result<boolean> {
    const owner = this.state.recordOwners.get(0);
    if (!owner || owner !== this.caller) {
      return { ok: false, value: false };
    }
    this.state.auditEnabled = enabled;
    this.logAudit("audit-toggled", 0, enabled ? "enabled" : "disabled");
    return { ok: true, value: true };
  }

  hasAccess(recordId: number, user: string): boolean {
    const key = `${recordId}-${user}`;
    const grant = this.state.accessGrants.get(key);
    if (!grant || grant.revoked) {
      return false;
    }
    if (grant.expiry !== null && grant.expiry < this.blockHeight) {
      return false;
    }
    return true;
  }

  private logAudit(action: string, recordId: number, details: string): void {
    if (!this.state.auditEnabled) {
      return;
    }
    const id = this.state.nextAuditId;
    this.state.auditLogs.set(id, {
      action,
      actor: this.caller,
      recordId,
      timestamp: this.blockHeight,
      details,
    });
    this.state.nextAuditId++;
  }

  getGrant(recordId: number, grantee: string): Grant | null {
    const key = `${recordId}-${grantee}`;
    return this.state.accessGrants.get(key) || null;
  }

  getRecordOwner(recordId: number): string | null {
    return this.state.recordOwners.get(recordId) || null;
  }

  getGrantCount(recordId: number): number {
    return this.state.recordGrantCounts.get(recordId) || 0;
  }

  isGroupMember(groupId: number, member: string): boolean {
    const key = `${groupId}-${member}`;
    return this.state.groupMembers.get(key) || false;
  }

  getGroup(groupId: number): Group | null {
    return this.state.groups.get(groupId) || null;
  }

  getAuditLog(logId: number): AuditLog | null {
    return this.state.auditLogs.get(logId) || null;
  }
}

describe("AccessContract", () => {
  let contract: AccessContractMock;

  beforeEach(() => {
    contract = new AccessContractMock();
    contract.reset();
  });

  it("sets record owner successfully", () => {
    const result = contract.setRecordOwner(1);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.getRecordOwner(1)).toBe("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM");
  });

  it("rejects setting owner for existing record", () => {
    contract.setRecordOwner(1);
    const result = contract.setRecordOwner(1);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("grants access successfully", () => {
    contract.setRecordOwner(1);
    const result = contract.grantAccess(
      1,
      "ST2PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM",
      "individual",
      null,
      "Consultation sharing",
      1
    );
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const grant = contract.getGrant(1, "ST2PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM");
    expect(grant?.grantType).toBe("individual");
    expect(grant?.reason).toBe("Consultation sharing");
    expect(grant?.level).toBe(1);
    expect(grant?.revoked).toBe(false);
    expect(contract.getGrantCount(1)).toBe(1);
  });

  it("rejects grant by non-owner", () => {
    const result = contract.grantAccess(
      1,
      "ST2PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM",
      "individual",
      null,
      "Consultation sharing",
      1
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("rejects duplicate grant", () => {
    contract.setRecordOwner(1);
    contract.grantAccess(
      1,
      "ST2PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM",
      "individual",
      null,
      "Consultation sharing",
      1
    );
    const result = contract.grantAccess(
      1,
      "ST2PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM",
      "individual",
      null,
      "Consultation sharing",
      1
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("rejects invalid grant type", () => {
    contract.setRecordOwner(1);
    const result = contract.grantAccess(
      1,
      "ST2PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM",
      "invalid",
      null,
      "Consultation sharing",
      1
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("rejects invalid expiry", () => {
    contract.setRecordOwner(1);
    contract.blockHeight = 10;
    const result = contract.grantAccess(
      1,
      "ST2PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM",
      "temporary",
      5,
      "Consultation sharing",
      1
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("rejects invalid reason length", () => {
    contract.setRecordOwner(1);
    const result = contract.grantAccess(
      1,
      "ST2PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM",
      "individual",
      null,
      "",
      1
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("rejects invalid access level", () => {
    contract.setRecordOwner(1);
    const result = contract.grantAccess(
      1,
      "ST2PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM",
      "individual",
      null,
      "Consultation sharing",
      4
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("rejects max grants exceeded", () => {
    contract.setRecordOwner(1);
    contract.state.maxGrantsPerRecord = 1;
    contract.grantAccess(
      1,
      "ST2PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM",
      "individual",
      null,
      "Consultation sharing",
      1
    );
    const result = contract.grantAccess(
      1,
      "ST3PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM",
      "individual",
      null,
      "Consultation sharing",
      1
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("revokes access successfully", () => {
    contract.setRecordOwner(1);
    contract.grantAccess(
      1,
      "ST2PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM",
      "individual",
      null,
      "Consultation sharing",
      1
    );
    const result = contract.revokeAccess(1, "ST2PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const grant = contract.getGrant(1, "ST2PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM");
    expect(grant?.revoked).toBe(true);
  });

  it("rejects revoke by non-owner", () => {
    contract.setRecordOwner(1);
    contract.grantAccess(
      1,
      "ST2PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM",
      "individual",
      null,
      "Consultation sharing",
      1
    );
    contract.caller = "ST3PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM";
    const result = contract.revokeAccess(1, "ST2PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("rejects revoke non-existent grant", () => {
    contract.setRecordOwner(1);
    const result = contract.revokeAccess(1, "ST2PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("creates group successfully", () => {
    const result = contract.createGroup("HealthGroup");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(0);
    const group = contract.getGroup(0);
    expect(group?.name).toBe("HealthGroup");
    expect(group?.creator).toBe("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM");
    expect(group?.active).toBe(true);
  });

  it("rejects group with invalid name length", () => {
    const result = contract.createGroup("");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(0);
  });

  it("adds group member successfully", () => {
    contract.createGroup("HealthGroup");
    const result = contract.addGroupMember(0, "ST2PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.isGroupMember(0, "ST2PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM")).toBe(true);
  });

  it("rejects add member by non-creator", () => {
    contract.createGroup("HealthGroup");
    contract.caller = "ST3PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM";
    const result = contract.addGroupMember(0, "ST2PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("grants group access successfully", () => {
    contract.setRecordOwner(1);
    contract.createGroup("HealthGroup");
    const result = contract.grantGroupAccess(1, 0, null, "Group consultation", 2);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const grant = contract.getGrant(1, "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM");
    expect(grant?.grantType).toBe("group");
    expect(grant?.level).toBe(2);
  });

  it("rejects group access for non-existent group", () => {
    contract.setRecordOwner(1);
    const result = contract.grantGroupAccess(1, 999, null, "Group consultation", 2);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("sets max grants successfully", () => {
    contract.setRecordOwner(0);
    const result = contract.setMaxGrants(100);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.maxGrantsPerRecord).toBe(100);
  });

  it("rejects set max grants by non-owner", () => {
    const result = contract.setMaxGrants(100);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("toggles audit successfully", () => {
    contract.setRecordOwner(0);
    const result = contract.toggleAudit(false);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.auditEnabled).toBe(false);
  });

  it("checks access correctly", () => {
    contract.setRecordOwner(1);
    contract.grantAccess(
      1,
      "ST2PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM",
      "individual",
      null,
      "Consultation sharing",
      1
    );
    expect(contract.hasAccess(1, "ST2PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM")).toBe(true);
    contract.revokeAccess(1, "ST2PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM");
    expect(contract.hasAccess(1, "ST2PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM")).toBe(false);
    contract.blockHeight = 20;
    contract.grantAccess(
      1,
      "ST3PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM",
      "temporary",
      15,
      "Temp sharing",
      1
    );
    expect(contract.hasAccess(1, "ST3PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM")).toBe(false);
  });
});