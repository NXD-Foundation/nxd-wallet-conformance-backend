import { expect } from "chai";
import path from "path";
import { resolveDeviceKeyPath, resolveAttestDeviceKeyPaths, DEFAULT_DEVICE_KEY_PATH } from "../src/lib/deviceKeyPaths.js";

describe("deviceKeyPaths", () => {
  it("resolveDeviceKeyPath prefers explicit --key / keyPath", () => {
    expect(resolveDeviceKeyPath("/tmp/only-device.json")).to.equal("/tmp/only-device.json");
  });

  it("resolveDeviceKeyPath uses default path when unset", () => {
    const prev = process.env.WALLET_DEVICE_KEY_PATH;
    delete process.env.WALLET_DEVICE_KEY_PATH;
    try {
      expect(resolveDeviceKeyPath(undefined)).to.equal(DEFAULT_DEVICE_KEY_PATH);
      expect(resolveDeviceKeyPath("")).to.equal(DEFAULT_DEVICE_KEY_PATH);
    } finally {
      if (prev !== undefined) process.env.WALLET_DEVICE_KEY_PATH = prev;
    }
  });

  it("resolveAttestDeviceKeyPaths: single path matches resolveDeviceKeyPath", () => {
    expect(resolveAttestDeviceKeyPaths("/tmp/a.json", 1)).to.deep.equal(["/tmp/a.json"]);
  });

  it("resolveAttestDeviceKeyPaths: N>1 derives stem-0..stem-(N-1) beside base", () => {
    const got = resolveAttestDeviceKeyPaths("/var/foo/device-key.json", 3);
    expect(got).to.deep.equal([
      path.join("/var/foo", "device-key-0.json"),
      path.join("/var/foo", "device-key-1.json"),
      path.join("/var/foo", "device-key-2.json"),
    ]);
  });
});
