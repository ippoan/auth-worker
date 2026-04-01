import { vi } from "vitest";

export function createMockAuthClient() {
  return {
    login: vi.fn(),
    loginWithGoogle: vi.fn(),
    loginWithSsoProvider: vi.fn(),
    resolveSsoProvider: vi.fn(),
    switchOrganization: vi.fn(),
  };
}

export function createMockOrganizationClient() {
  return {
    listMyOrganizations: vi.fn(),
  };
}

export function createMockAccessRequestClient() {
  return {
    getOrganizationBySlug: vi.fn(),
    createAccessRequest: vi.fn(),
    listAccessRequests: vi.fn(),
    approveAccessRequest: vi.fn(),
    declineAccessRequest: vi.fn(),
  };
}

export function createMockUserClient() {
  return {
    listUsers: vi.fn(),
    listInvitations: vi.fn(),
    inviteUser: vi.fn(),
    deleteInvitation: vi.fn(),
    deleteUser: vi.fn(),
  };
}
