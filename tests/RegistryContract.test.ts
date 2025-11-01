import { describe, it, expect, beforeEach } from "vitest";
import { stringUtf8CV, uintCV, principalCV, bufferCV, someCV, noneCV } from "@stacks/transactions";

const ERR_ALREADY_REGISTERED = 100;
const ERR_NOT_AUTHORIZED = 101;
const ERR_INVALID_CREDENTIALS_HASH = 102;
const ERR_INVALID_SPECIALTY = 103;
const ERR_INVALID_LOCATION = 104;
const ERR_INVALID_VERIFICATION_CODE = 105;
const ERR_DOCTOR_NOT_VERIFIED = 106;
const ERR_INVALID_UPDATE_PARAM = 107;
const ERR_MAX_USERS_EXCEEDED = 108;
const ERR_AUTHORITY_NOT_SET = 109;
const ERR_INVALID_ROLE = 110;
const ERR_VERIFICATION_EXPIRED = 111;
const ERR_INVALID_TIMESTAMP = 112;

interface User {
  id: number;
  role: number;
  credentialsHash?: Buffer | null;
  specialty?: string | null;
  location?: string | null;
  registeredAt: number;
  verified: boolean;
  verificationCode?: Buffer | null;
  verificationTimestamp?: number | null;
}

interface VerificationRequest {
  code: Buffer;
  timestamp: number;
  expiresAt: number;
}

interface Result<T> {
  ok: boolean;
  value: T;
}

class RegistryContractMock {
  state: {
    nextUserId: number;
    maxUsers: number;
    registrationFee: number;
    authorityContract: string | null;
    verificationExpiryBlocks: number;
    users: Map<string, User>;
    usersById: Map<number, string>;
    doctorSpecialties: Map<string, boolean>;
    verificationRequests: Map<string, VerificationRequest>;
  } = {
    nextUserId: 0,
    maxUsers: 5000,
    registrationFee: 500,
    authorityContract: null,
    verificationExpiryBlocks: 1440,
    users: new Map(),
    usersById: new Map(),
    doctorSpecialties: new Map(),
    verificationRequests: new Map(),
  };
  blockHeight: number = 0;
  caller: string = "ST1TEST";
  deployer: string = "SP000000000000000000002Q6VF78";
  stxTransfers: Array<{ amount: number; from: string; to: string | null }> = [];

  constructor() {
    this.reset();
  }

  reset() {
    this.state = {
      nextUserId: 0,
      maxUsers: 5000,
      registrationFee: 500,
      authorityContract: null,
      verificationExpiryBlocks: 1440,
      users: new Map(),
      usersById: new Map(),
      doctorSpecialties: new Map(),
      verificationRequests: new Map(),
    };
    this.blockHeight = 0;
    this.caller = "ST1TEST";
    this.stxTransfers = [];
  }

  isVerifiedAuthority(caller: string): boolean {
    return this.state.authorityContract === caller;
  }

  setAuthorityContract(contractPrincipal: string): Result<boolean> {
    if (this.caller !== this.deployer) {
      return { ok: false, value: false };
    }
    if (this.state.authorityContract !== null) {
      return { ok: false, value: false };
    }
    this.state.authorityContract = contractPrincipal;
    return { ok: true, value: true };
  }

  setMaxUsers(newMax: number): Result<boolean> {
    if (!this.isVerifiedAuthority(this.caller)) {
      return { ok: false, value: false };
    }
    if (newMax <= 0) {
      return { ok: false, value: false };
    }
    this.state.maxUsers = newMax;
    return { ok: true, value: true };
  }

  setRegistrationFee(newFee: number): Result<boolean> {
    if (!this.isVerifiedAuthority(this.caller)) {
      return { ok: false, value: false };
    }
    if (newFee < 0) {
      return { ok: false, value: false };
    }
    this.state.registrationFee = newFee;
    return { ok: true, value: true };
  }

  setVerificationExpiry(blocks: number): Result<boolean> {
    if (!this.isVerifiedAuthority(this.caller)) {
      return { ok: false, value: false };
    }
    if (blocks <= 0) {
      return { ok: false, value: false };
    }
    this.state.verificationExpiryBlocks = blocks;
    return { ok: true, value: true };
  }

  registerPatient(): Result<number> {
    if (this.state.nextUserId >= this.state.maxUsers) {
      return { ok: false, value: ERR_MAX_USERS_EXCEEDED };
    }
    if (this.state.users.has(this.caller)) {
      return { ok: false, value: ERR_ALREADY_REGISTERED };
    }
    if (!this.state.authorityContract) {
      return { ok: false, value: ERR_AUTHORITY_NOT_SET };
    }
    this.stxTransfers.push({ amount: this.state.registrationFee, from: this.caller, to: this.state.authorityContract });

    const id = this.state.nextUserId;
    const user: User = {
      id,
      role: 1,
      registeredAt: this.blockHeight,
      verified: true,
    };
    this.state.users.set(this.caller, user);
    this.state.usersById.set(id, this.caller);
    this.state.nextUserId++;
    return { ok: true, value: id };
  }

  registerDoctor(
    credentialsHash: Buffer,
    specialty: string,
    location: string
  ): Result<number> {
    if (this.state.nextUserId >= this.state.maxUsers) {
      return { ok: false, value: ERR_MAX_USERS_EXCEEDED };
    }
    if (this.state.users.has(this.caller)) {
      return { ok: false, value: ERR_ALREADY_REGISTERED };
    }
    if (credentialsHash.length !== 32) {
      return { ok: false, value: ERR_INVALID_CREDENTIALS_HASH };
    }
    if (!specialty || specialty.length > 50) {
      return { ok: false, value: ERR_INVALID_SPECIALTY };
    }
    if (!location || location.length > 100) {
      return { ok: false, value: ERR_INVALID_LOCATION };
    }
    if (!this.state.authorityContract) {
      return { ok: false, value: ERR_AUTHORITY_NOT_SET };
    }
    this.stxTransfers.push({ amount: this.state.registrationFee, from: this.caller, to: this.state.authorityContract });

    const id = this.state.nextUserId;
    const user: User = {
      id,
      role: 2,
      credentialsHash,
      specialty,
      location,
      registeredAt: this.blockHeight,
      verified: false,
    };
    this.state.users.set(this.caller, user);
    this.state.usersById.set(id, this.caller);
    this.state.doctorSpecialties.set(`${this.caller}:${specialty}`, true);
    this.state.nextUserId++;
    return { ok: true, value: id };
  }

  requestVerification(code: Buffer, timestamp: number): Result<boolean> {
    const user = this.state.users.get(this.caller);
    if (!user) {
      return { ok: false, value: ERR_ALREADY_REGISTERED };
    }
    if (user.role !== 2) {
      return { ok: false, value: ERR_NOT_AUTHORIZED };
    }
    if (user.verified) {
      return { ok: false, value: ERR_DOCTOR_NOT_VERIFIED };
    }
    if (code.length !== 16) {
      return { ok: false, value: ERR_INVALID_VERIFICATION_CODE };
    }
    if (timestamp < this.blockHeight) {
      return { ok: false, value: ERR_INVALID_TIMESTAMP };
    }
    const expiresAt = timestamp + this.state.verificationExpiryBlocks;
    const req: VerificationRequest = { code, timestamp, expiresAt };
    this.state.verificationRequests.set(this.caller, req);
    this.state.users.set(this.caller, { ...user, verificationCode: code, verificationTimestamp: timestamp });
    return { ok: true, value: true };
  }

  verifyDoctor(user: string, code: Buffer): Result<boolean> {
    if (!this.isVerifiedAuthority(this.caller)) {
      return { ok: false, value: ERR_NOT_AUTHORIZED };
    }
    const userData = this.state.users.get(user);
    if (!userData) {
      return { ok: false, value: ERR_ALREADY_REGISTERED };
    }
    const req = this.state.verificationRequests.get(user);
    if (!req) {
      return { ok: false, value: ERR_INVALID_VERIFICATION_CODE };
    }
    if (!Buffer.from(req.code).equals(code)) {
      return { ok: false, value: ERR_INVALID_VERIFICATION_CODE };
    }
    if (this.blockHeight > req.expiresAt) {
      return { ok: false, value: ERR_VERIFICATION_EXPIRED };
    }
    if (userData.role !== 2) {
      return { ok: false, value: ERR_NOT_AUTHORIZED };
    }
    if (userData.verified) {
      return { ok: false, value: ERR_DOCTOR_NOT_VERIFIED };
    }
    this.state.users.set(user, { ...userData, verified: true });
    this.state.verificationRequests.delete(user);
    return { ok: true, value: true };
  }

  updateUserLocation(newLocation: string): Result<boolean> {
    const user = this.state.users.get(this.caller);
    if (!user) {
      return { ok: false, value: ERR_ALREADY_REGISTERED };
    }
    if (!newLocation || newLocation.length > 100) {
      return { ok: false, value: ERR_INVALID_LOCATION };
    }
    this.state.users.set(this.caller, { ...user, location: newLocation });
    return { ok: true, value: true };
  }

  updateUserSpecialty(newSpecialty: string): Result<boolean> {
    const user = this.state.users.get(this.caller);
    if (!user) {
      return { ok: false, value: ERR_ALREADY_REGISTERED };
    }
    if (user.role !== 2) {
      return { ok: false, value: ERR_NOT_AUTHORIZED };
    }
    if (!newSpecialty || newSpecialty.length > 50) {
      return { ok: false, value: ERR_INVALID_SPECIALTY };
    }
    this.state.users.set(this.caller, { ...user, specialty: newSpecialty });
    this.state.doctorSpecialties.set(`${this.caller}:${newSpecialty}`, true);
    return { ok: true, value: true };
  }

  getUser(user: string): User | null {
    return this.state.users.get(user) || null;
  }

  getUserById(id: number): User | null {
    const principal = this.state.usersById.get(id);
    return principal ? this.state.users.get(principal) || null : null;
  }

  isUserRegistered(user: string): boolean {
    return this.state.users.has(user);
  }

  isDoctorVerified(user: string): boolean {
    const userData = this.state.users.get(user);
    return userData ? (userData.role === 2 && userData.verified) : false;
  }

  getUserCount(): Result<number> {
    return { ok: true, value: this.state.nextUserId };
  }
}

describe("RegistryContract", () => {
  let contract: RegistryContractMock;

  beforeEach(() => {
    contract = new RegistryContractMock();
    contract.reset();
  });

  it("registers a patient successfully", () => {
    contract.caller = contract.deployer;
    contract.setAuthorityContract("ST2AUTH");
    contract.caller = "ST1TEST";
    const result = contract.registerPatient();
    expect(result.ok).toBe(true);
    expect(result.value).toBe(0);

    const user = contract.getUser("ST1TEST");
    expect(user?.role).toBe(1);
    expect(user?.registeredAt).toBe(0);
    expect(user?.verified).toBe(true);
    expect(contract.stxTransfers).toEqual([{ amount: 500, from: "ST1TEST", to: "ST2AUTH" }]);
  });

  it("rejects patient registration if already registered", () => {
    contract.caller = contract.deployer;
    contract.setAuthorityContract("ST2AUTH");
    contract.caller = "ST1TEST";
    contract.registerPatient();
    const result = contract.registerPatient();
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_ALREADY_REGISTERED);
  });

  it("rejects patient registration without authority", () => {
    const result = contract.registerPatient();
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_AUTHORITY_NOT_SET);
  });

  it("registers a doctor successfully", () => {
    contract.caller = contract.deployer;
    contract.setAuthorityContract("ST2AUTH");
    contract.caller = "ST1TEST";
    const hash = Buffer.from("deadbeef".repeat(8), "hex");
    const result = contract.registerDoctor(hash, "Cardiology", "New York");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(0);

    const user = contract.getUser("ST1TEST");
    expect(user?.role).toBe(2);
    expect(user?.credentialsHash?.equals(hash)).toBe(true);
    expect(user?.specialty).toBe("Cardiology");
    expect(user?.location).toBe("New York");
    expect(user?.verified).toBe(false);
    expect(contract.stxTransfers).toEqual([{ amount: 500, from: "ST1TEST", to: "ST2AUTH" }]);
    expect(contract.state.doctorSpecialties.get("ST1TEST:Cardiology")).toBe(true);
  });

  it("rejects doctor registration with invalid hash", () => {
    contract.caller = contract.deployer;
    contract.setAuthorityContract("ST2AUTH");
    contract.caller = "ST1TEST";
    const shortHash = Buffer.from("deadbeef", "hex");
    const result = contract.registerDoctor(shortHash, "Cardiology", "New York");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_CREDENTIALS_HASH);
  });

  it("rejects doctor registration with invalid specialty", () => {
    contract.caller = contract.deployer;
    contract.setAuthorityContract("ST2AUTH");
    contract.caller = "ST1TEST";
    const hash = Buffer.from("deadbeef".repeat(8), "hex");
    const result = contract.registerDoctor(hash, "A".repeat(51), "New York");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_SPECIALTY);
  });

  it("rejects doctor registration if already registered", () => {
    contract.caller = contract.deployer;
    contract.setAuthorityContract("ST2AUTH");
    contract.caller = "ST1TEST";
    const hash = Buffer.from("deadbeef".repeat(8), "hex");
    contract.registerDoctor(hash, "Cardiology", "New York");
    const result = contract.registerDoctor(hash, "Neurology", "LA");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_ALREADY_REGISTERED);
  });

  it("rejects verification request for non-doctor", () => {
    contract.caller = contract.deployer;
    contract.setAuthorityContract("ST2AUTH");
    contract.caller = "ST1TEST";
    contract.registerPatient();
    const code = Buffer.from("vercode12345678", "utf8");
    const result = contract.requestVerification(code, 100);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_NOT_AUTHORIZED);
  });

  it("rejects doctor verification with wrong code", () => {
    contract.caller = contract.deployer;
    contract.setAuthorityContract("ST2AUTH");
    contract.caller = "ST1TEST";
    const hash = Buffer.from("deadbeef".repeat(8), "hex");
    contract.registerDoctor(hash, "Cardiology", "New York");
    const code = Buffer.from("vercode12345678", "utf8");
    contract.requestVerification(code, 100);
    contract.caller = "ST2AUTH";
    const wrongCode = Buffer.from("wrongcode123456", "utf8");
    const result = contract.verifyDoctor("ST1TEST", wrongCode);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_VERIFICATION_CODE);
  });

  it("rejects verification by non-authority", () => {
    contract.caller = contract.deployer;
    contract.setAuthorityContract("ST2AUTH");
    contract.caller = "ST1TEST";
    const hash = Buffer.from("deadbeef".repeat(8), "hex");
    contract.registerDoctor(hash, "Cardiology", "New York");
    const code = Buffer.from("vercode12345678", "utf8");
    contract.requestVerification(code, 100);
    contract.caller = "ST3FAKE";
    const result = contract.verifyDoctor("ST1TEST", code);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_NOT_AUTHORIZED);
  });

  it("updates user location successfully", () => {
    contract.caller = contract.deployer;
    contract.setAuthorityContract("ST2AUTH");
    contract.caller = "ST1TEST";
    contract.registerPatient();
    const result = contract.updateUserLocation("Updated City");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);

    const user = contract.getUser("ST1TEST");
    expect(user?.location).toBe("Updated City");
  });

  it("rejects location update with invalid length", () => {
    contract.caller = contract.deployer;
    contract.setAuthorityContract("ST2AUTH");
    contract.caller = "ST1TEST";
    contract.registerPatient();
    const result = contract.updateUserLocation("A".repeat(101));
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_LOCATION);
  });

  it("rejects specialty update for non-doctor", () => {
    contract.caller = contract.deployer;
    contract.setAuthorityContract("ST2AUTH");
    contract.caller = "ST1TEST";
    contract.registerPatient();
    const result = contract.updateUserSpecialty("Surgery");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_NOT_AUTHORIZED);
  });

  it("rejects specialty update with invalid length", () => {
    contract.caller = contract.deployer;
    contract.setAuthorityContract("ST2AUTH");
    contract.caller = "ST1TEST";
    const hash = Buffer.from("deadbeef".repeat(8), "hex");
    contract.registerDoctor(hash, "Cardiology", "New York");
    const result = contract.updateUserSpecialty("A".repeat(51));
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_SPECIALTY);
  });

  it("sets authority contract successfully", () => {
    contract.caller = "SP000000000000000000002Q6VF78";
    const result = contract.setAuthorityContract("ST2AUTH");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.authorityContract).toBe("ST2AUTH");
  });

  it("rejects setting authority if already set", () => {
    contract.caller = "SP000000000000000000002Q6VF78";
    contract.setAuthorityContract("ST2AUTH");
    const result = contract.setAuthorityContract("ST3NEW");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("sets registration fee successfully", () => {
    contract.caller = contract.deployer;
    contract.setAuthorityContract("ST2AUTH");
    contract.caller = "ST2AUTH";
    const result = contract.setRegistrationFee(1000);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.registrationFee).toBe(1000);
  });

  it("checks user registration correctly", () => {
    contract.caller = contract.deployer;
    contract.setAuthorityContract("ST2AUTH");
    contract.caller = "ST1TEST";
    contract.registerPatient();
    expect(contract.isUserRegistered("ST1TEST")).toBe(true);
    expect(contract.isUserRegistered("ST2FAKE")).toBe(false);
  });

  it("retrieves user by ID correctly", () => {
    contract.caller = contract.deployer;
    contract.setAuthorityContract("ST2AUTH");
    contract.caller = "ST1TEST";
    contract.registerPatient();
    const user = contract.getUserById(0);
    expect(user?.id).toBe(0);
    expect(user?.role).toBe(1);
  });

  it("rejects max users exceeded", () => {
    contract.caller = contract.deployer;
    contract.setAuthorityContract("ST2AUTH");
    contract.caller = "ST1TEST";
    contract.state.maxUsers = 1;
    contract.registerPatient();
    const result = contract.registerPatient();
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_MAX_USERS_EXCEEDED);
  });
});