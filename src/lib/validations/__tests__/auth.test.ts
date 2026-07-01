import { describe, it, expect } from "vitest";
import { loginSchema, signupSchema } from "../auth";

describe("loginSchema", () => {
  it("accepts a valid email and password", () => {
    const result = loginSchema.safeParse({ email: "buyer@flexvault.in", password: "FlexVault@123" });
    expect(result.success).toBe(true);
  });

  it("rejects an invalid email", () => {
    const result = loginSchema.safeParse({ email: "not-an-email", password: "FlexVault@123" });
    expect(result.success).toBe(false);
  });

  it("rejects an empty password", () => {
    const result = loginSchema.safeParse({ email: "buyer@flexvault.in", password: "" });
    expect(result.success).toBe(false);
  });
});

describe("signupSchema", () => {
  const base = {
    name: "Aditya Sharma",
    email: "buyer@flexvault.in",
    password: "FlexVault@123",
    confirmPassword: "FlexVault@123",
    role: "BUYER" as const,
  };

  it("accepts valid buyer signup data", () => {
    expect(signupSchema.safeParse(base).success).toBe(true);
  });

  it("accepts SELLER as a role", () => {
    expect(signupSchema.safeParse({ ...base, role: "SELLER" }).success).toBe(true);
  });

  it("rejects a password under 8 characters", () => {
    const result = signupSchema.safeParse({ ...base, password: "short", confirmPassword: "short" });
    expect(result.success).toBe(false);
  });

  it("rejects mismatched passwords", () => {
    const result = signupSchema.safeParse({ ...base, confirmPassword: "SomethingElse@123" });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.flatten().fieldErrors.confirmPassword).toBeTruthy();
    }
  });

  it("rejects an invalid role", () => {
    const result = signupSchema.safeParse({ ...base, role: "ADMIN" });
    expect(result.success).toBe(false);
  });
});
