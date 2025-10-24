import { describe, it, expect, beforeEach } from "vitest";
import { bufferCV, uintCV, stringUtf8CV } from "@stacks/transactions";

const ERR_INVALID_HASH = 101;
const ERR_INVALID_PATIENT = 102;
const ERR_INVALID_DOCTOR = 103;
const ERR_RECORD_NOT_FOUND = 104;
const ERR_MAX_RECORDS_EXCEEDED = 113;
const ERR_ACCESS_DENIED = 108;
const ERR_INVALID_RECORD_TYPE = 109;
const ERR_INVALID_ENCRYPTION_KEY = 110;
const ERR_INVALID_METADATA = 107;
const ERR_RECORD_LOCKED = 115;
const ERR_INVALID_UPDATE_PARAM = 112;

const RECORD_TYPE_CONSULTATION = 1;
const RECORD_TYPE_PRESCRIPTION = 2;
const RECORD_STATUS_ACTIVE = 1;

interface Record {
  patient: string;
  doctor: string;
  recordType: number;
  recordHash: Uint8Array;
  encryptionKeyHash: Uint8Array;
  timestamp: number;
  status: number;
  metadata: string;
  version: number;
  revisionCount: number;
  locked: boolean;
}

interface RecordRevision {
  recordHash: Uint8Array;
  encryptionKeyHash: Uint8Array;
  timestamp: number;
  editor: string;
  changeNote: string;
}

interface Result<T> {
  ok: boolean;
  value: T;
}

class RecordContractMock {
  state: {
    nextRecordId: number;
    maxRecordsPerPatient: number;
    records: Map<number, Record>;
    recordRevisions: Map<string, RecordRevision>;
    patientRecordIndex: Map<string, boolean>;
    doctorRecordIndex: Map<string, boolean>;
    recordAccessLog: Map<string, { timestamp: number; accessType: string }>;
  } = {
    nextRecordId: 1,
    maxRecordsPerPatient: 1000,
    records: new Map(),
    recordRevisions: new Map(),
    patientRecordIndex: new Map(),
    doctorRecordIndex: new Map(),
    recordAccessLog: new Map(),
  };
  blockHeight: number = 100;
  caller: string = "STDOCTOR1";

  constructor() {
    this.reset();
  }

  reset() {
    this.state = {
      nextRecordId: 1,
      maxRecordsPerPatient: 1000,
      records: new Map(),
      recordRevisions: new Map(),
      patientRecordIndex: new Map(),
      doctorRecordIndex: new Map(),
      recordAccessLog: new Map(),
    };
    this.blockHeight = 100;
    this.caller = "STDOCTOR1";
  }

  private getPatientRecordCount(patient: string): number {
    let count = 0;
    for (let i = 1; i <= 10; i++) {
      if (this.state.patientRecordIndex.get(`${patient}-${i}`)) count++;
    }
    return count;
  }

  storeRecord(
    patient: string,
    recordType: number,
    recordHash: Uint8Array,
    encryptionKeyHash: Uint8Array,
    metadata: string
  ): Result<number> {
    if (patient === "SP000000000000000000002Q6VF78") return { ok: false, value: ERR_INVALID_PATIENT };
    if (this.caller === "SP000000000000000000002Q6VF78") return { ok: false, value: ERR_INVALID_DOCTOR };
    if (![1, 2, 3, 4, 5].includes(recordType)) return { ok: false, value: ERR_INVALID_RECORD_TYPE };
    if (recordHash.length === 0) return { ok: false, value: ERR_INVALID_HASH };
    if (encryptionKeyHash.length === 0) return { ok: false, value: ERR_INVALID_ENCRYPTION_KEY };
    if (metadata.length === 0 || metadata.length > 256) return { ok: false, value: ERR_INVALID_METADATA };
    if (this.getPatientRecordCount(patient) >= this.state.maxRecordsPerPatient)
      return { ok: false, value: ERR_MAX_RECORDS_EXCEEDED };

    const recordId = this.state.nextRecordId;
    const record: Record = {
      patient,
      doctor: this.caller,
      recordType,
      recordHash,
      encryptionKeyHash,
      timestamp: this.blockHeight,
      status: RECORD_STATUS_ACTIVE,
      metadata,
      version: 1,
      revisionCount: 0,
      locked: false,
    };
    this.state.records.set(recordId, record);
    this.state.patientRecordIndex.set(`${patient}-${recordId}`, true);
    this.state.doctorRecordIndex.set(`${this.caller}-${recordId}`, true);
    this.state.nextRecordId++;
    return { ok: true, value: recordId };
  }

  updateRecordHash(
    recordId: number,
    newRecordHash: Uint8Array,
    newEncryptionKeyHash: Uint8Array,
    changeNote: string
  ): Result<number> {
    const record = this.state.records.get(recordId);
    if (!record) return { ok: false, value: ERR_RECORD_NOT_FOUND };
    if (record.doctor !== this.caller) return { ok: false, value: ERR_ACCESS_DENIED };
    if (record.locked) return { ok: false, value: ERR_RECORD_LOCKED };
    if (newRecordHash.length === 0) return { ok: false, value: ERR_INVALID_HASH };
    if (newEncryptionKeyHash.length === 0) return { ok: false, value: ERR_INVALID_ENCRYPTION_KEY };
    if (changeNote.length > 128) return { ok: false, value: ERR_INVALID_UPDATE_PARAM };

    const newRevision = record.revisionCount + 1;
    const revisionKey = `${recordId}-${newRevision}`;
    this.state.recordRevisions.set(revisionKey, {
      recordHash: newRecordHash,
      encryptionKeyHash: newEncryptionKeyHash,
      timestamp: this.blockHeight,
      editor: this.caller,
      changeNote,
    });
    this.state.records.set(recordId, {
      ...record,
      recordHash: newRecordHash,
      encryptionKeyHash: newEncryptionKeyHash,
      version: record.version + 1,
      revisionCount: newRevision,
    });
    return { ok: true, value: newRevision };
  }

  lockRecord(recordId: number): Result<boolean> {
    const record = this.state.records.get(recordId);
    if (!record) return { ok: false, value: ERR_RECORD_NOT_FOUND };
    if (record.patient !== this.caller && record.doctor !== this.caller)
      return { ok: false, value: ERR_ACCESS_DENIED };
    if (record.locked) return { ok: false, value: ERR_RECORD_LOCKED };
    this.state.records.set(recordId, { ...record, locked: true });
    return { ok: true, value: true };
  }

  archiveRecord(recordId: number): Result<boolean> {
    const record = this.state.records.get(recordId);
    if (!record) return { ok: false, value: ERR_RECORD_NOT_FOUND };
    if (record.patient !== this.caller) return { ok: false, value: ERR_ACCESS_DENIED };
    if (record.status !== RECORD_STATUS_ACTIVE) return { ok: false, value: 111 };
    this.state.records.set(recordId, { ...record, status: 2 });
    return { ok: true, value: true };
  }

  logAccess(recordId: number, accessType: string): Result<boolean> {
    this.state.recordAccessLog.set(`${recordId}-${this.caller}`, {
      timestamp: this.blockHeight,
      accessType,
    });
    return { ok: true, value: true };
  }

  getRecord(recordId: number): Record | null {
    return this.state.records.get(recordId) || null;
  }

  getLatestRevisionId(recordId: number): Result<number> {
    const record = this.state.records.get(recordId);
    return record ? { ok: true, value: record.revisionCount } : { ok: false, value: ERR_RECORD_NOT_FOUND };
  }
}

describe("RecordContract", () => {
  let contract: RecordContractMock;

  beforeEach(() => {
    contract = new RecordContractMock();
    contract.reset();
  });

  it("stores a consultation record successfully", () => {
    const result = contract.storeRecord(
      "STPATIENT1",
      RECORD_TYPE_CONSULTATION,
      new Uint8Array(32).fill(1),
      new Uint8Array(32).fill(2),
      "Initial consultation notes"
    );
    expect(result.ok).toBe(true);
    expect(result.value).toBe(1);

    const record = contract.getRecord(1);
    expect(record?.patient).toBe("STPATIENT1");
    expect(record?.doctor).toBe("STDOCTOR1");
    expect(record?.recordType).toBe(RECORD_TYPE_CONSULTATION);
    expect(record?.status).toBe(RECORD_STATUS_ACTIVE);
    expect(record?.version).toBe(1);
    expect(record?.locked).toBe(false);
  });

  it("rejects record with invalid patient principal", () => {
    const result = contract.storeRecord(
      "SP000000000000000000002Q6VF78",
      RECORD_TYPE_CONSULTATION,
      new Uint8Array(32).fill(1),
      new Uint8Array(32).fill(2),
      "Notes"
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_PATIENT);
  });

  it("rejects record with invalid record type", () => {
    const result = contract.storeRecord(
      "STPATIENT1",
      99,
      new Uint8Array(32).fill(1),
      new Uint8Array(32).fill(2),
      "Notes"
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_RECORD_TYPE);
  });

  it("rejects record with empty hash", () => {
    const result = contract.storeRecord(
      "STPATIENT1",
      RECORD_TYPE_CONSULTATION,
      new Uint8Array(0),
      new Uint8Array(32).fill(2),
      "Notes"
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_HASH);
  });

  it("enforces max records per patient", () => {
    contract.state.maxRecordsPerPatient = 1;
    contract.storeRecord(
      "STPATIENT1",
      RECORD_TYPE_CONSULTATION,
      new Uint8Array(32).fill(1),
      new Uint8Array(32).fill(2),
      "First"
    );
    const result = contract.storeRecord(
      "STPATIENT1",
      RECORD_TYPE_PRESCRIPTION,
      new Uint8Array(32).fill(3),
      new Uint8Array(32).fill(4),
      "Second"
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_MAX_RECORDS_EXCEEDED);
  });

  it("updates record hash and creates revision", () => {
    contract.storeRecord(
      "STPATIENT1",
      RECORD_TYPE_CONSULTATION,
      new Uint8Array(32).fill(1),
      new Uint8Array(32).fill(2),
      "Initial"
    );
    const result = contract.updateRecordHash(
      1,
      new Uint8Array(32).fill(5),
      new Uint8Array(32).fill(6),
      "Updated diagnosis"
    );
    expect(result.ok).toBe(true);
    expect(result.value).toBe(1);

    const record = contract.getRecord(1);
    expect(record?.version).toBe(2);
    expect(record?.revisionCount).toBe(1);
  });

  it("rejects update by non-doctor", () => {
    contract.storeRecord(
      "STPATIENT1",
      RECORD_TYPE_CONSULTATION,
      new Uint8Array(32).fill(1),
      new Uint8Array(32).fill(2),
      "Initial"
    );
    contract.caller = "STHACKER";
    const result = contract.updateRecordHash(
      1,
      new Uint8Array(32).fill(5),
      new Uint8Array(32).fill(6),
      "Malicious"
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_ACCESS_DENIED);
  });

  it("locks record successfully", () => {
    contract.storeRecord(
      "STPATIENT1",
      RECORD_TYPE_CONSULTATION,
      new Uint8Array(32).fill(1),
      new Uint8Array(32).fill(2),
      "Initial"
    );
    const result = contract.lockRecord(1);
    expect(result.ok).toBe(true);

    const record = contract.getRecord(1);
    expect(record?.locked).toBe(true);
  });

  it("prevents update after lock", () => {
    contract.storeRecord(
      "STPATIENT1",
      RECORD_TYPE_CONSULTATION,
      new Uint8Array(32).fill(1),
      new Uint8Array(32).fill(2),
      "Initial"
    );
    contract.lockRecord(1);
    const result = contract.updateRecordHash(
      1,
      new Uint8Array(32).fill(5),
      new Uint8Array(32).fill(6),
      "Too late"
    );
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_RECORD_LOCKED);
  });

  it("archives record as patient", () => {
    contract.storeRecord(
      "STPATIENT1",
      RECORD_TYPE_CONSULTATION,
      new Uint8Array(32).fill(1),
      new Uint8Array(32).fill(2),
      "Initial"
    );
    contract.caller = "STPATIENT1";
    const result = contract.archiveRecord(1);
    expect(result.ok).toBe(true);

    const record = contract.getRecord(1);
    expect(record?.status).toBe(2);
  });

  it("logs access correctly", () => {
    contract.storeRecord(
      "STPATIENT1",
      RECORD_TYPE_CONSULTATION,
      new Uint8Array(32).fill(1),
      new Uint8Array(32).fill(2),
      "Initial"
    );
    contract.logAccess(1, "view");
    const log = contract.state.recordAccessLog.get(`1-STDOCTOR1`);
    expect(log?.accessType).toBe("view");
    expect(log?.timestamp).toBe(100);
  });

  it("returns latest revision id", () => {
    contract.storeRecord(
      "STPATIENT1",
      RECORD_TYPE_CONSULTATION,
      new Uint8Array(32).fill(1),
      new Uint8Array(32).fill(2),
      "Initial"
    );
    contract.updateRecordHash(
      1,
      new Uint8Array(32).fill(5),
      new Uint8Array(32).fill(6),
      "Update"
    );
    const result = contract.getLatestRevisionId(1);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(1);
  });
});