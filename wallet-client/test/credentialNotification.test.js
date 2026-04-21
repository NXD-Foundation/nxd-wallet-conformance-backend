import { expect } from "chai";
import {
  extractNotificationId,
  resolveNotificationEndpoint,
} from "../src/lib/credentialNotification.js";

describe("credentialNotification helpers", () => {
  describe("extractNotificationId", () => {
    it("returns string id from credential response envelope", () => {
      expect(
        extractNotificationId({
          credentials: [{ credential: "x.y.z" }],
          notification_id: "nid-1",
        }),
      ).to.equal("nid-1");
    });

    it("returns undefined when absent", () => {
      expect(extractNotificationId({ credentials: [] })).to.equal(undefined);
      expect(extractNotificationId(null)).to.equal(undefined);
    });
  });

  describe("resolveNotificationEndpoint", () => {
    it("prefers issuer metadata notification_endpoint", () => {
      expect(
        resolveNotificationEndpoint(
          { notification_endpoint: "https://as.example/notify" },
          "http://localhost:3000",
        ),
      ).to.equal("https://as.example/notify");
    });

    it("defaults to {apiBase}/notification", () => {
      expect(resolveNotificationEndpoint(undefined, "http://localhost:3000")).to.equal(
        "http://localhost:3000/notification",
      );
    });
  });
});
