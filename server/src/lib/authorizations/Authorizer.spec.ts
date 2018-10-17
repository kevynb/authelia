import Assert = require("assert");
import winston = require("winston");
import { ACLConfiguration } from "../configuration/schema/AclConfiguration";
import { Resource } from "./Resource";
import { Authorizer } from "./Authorizer";

describe("authorizations/Authorizer", function () {
  let Authorizer: Authorizer;

  describe("configuration is null", function() {
    it("should allow access to anything, anywhere for anybody", function() {
      Authorizer = new Authorizer(winston);

      Assert(Authorizer.isAccessAllowed(
        undefined, {domain: "home.example.com", path: "/"}, "user1", ["group1", "group2"]));
      Assert(Authorizer.isAccessAllowed(
        undefined, {domain: "home.example.com", path: "/abc"}, "user1", ["group1", "group2"]));
      Assert(Authorizer.isAccessAllowed(
        undefined, {domain: "home.example.com", path: "/"}, "user2", ["group1", "group2"]));
      Assert(Authorizer.isAccessAllowed(
        undefined, {domain: "admin.example.com", path: "/"}, "user3", ["group3"]));
    });
  });

  describe("configuration is not null", function () {
    beforeEach(function () {
      configuration = {
        default_policy: "deny",
        any: [],
        users: {},
        groups: {}
      };
      Authorizer = new Authorizer(configuration, winston);
    });

    describe("check access control with default policy to deny", function () {
      beforeEach(function () {
        configuration.default_policy = "deny";
      });

      it("should deny access when no rule is provided", function () {
        Assert(!Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/"}, "user1", ["group1"]));
      });

      it("should control access when multiple domain matcher is provided", function () {
        configuration.users["user1"] = [{
          domain: "*.mail.example.com",
          policy: "allow",
          resources: [".*"]
        }];
        Assert(!Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/"}, "user1", ["group1"]));
        Assert(Authorizer.isAccessAllowed(
          {domain: "mx1.mail.example.com", path: "/"}, "user1", ["group1"]));
        Assert(Authorizer.isAccessAllowed(
          {domain: "mx1.server.mail.example.com", path: "/"}, "user1", ["group1"]));
        Assert(!Authorizer.isAccessAllowed(
          {domain: "mail.example.com", path: "/"}, "user1", ["group1"]));
      });

      it("should allow access to all resources when resources is not provided", function () {
        configuration.users["user1"] = [{
          domain: "*.mail.example.com",
          policy: "allow"
        }];
        Assert(!Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/"}, "user1", ["group1"]));
        Assert(Authorizer.isAccessAllowed(
          {domain: "mx1.mail.example.com", path: "/"}, "user1", ["group1"]));
        Assert(Authorizer.isAccessAllowed(
          {domain: "mx1.server.mail.example.com", path: "/"}, "user1", ["group1"]));
        Assert(!Authorizer.isAccessAllowed(
          {domain: "mail.example.com", path: "/"}, "user1", ["group1"]));
      });

      describe("check user rules", function () {
        it("should allow access when user has a matching allowing rule", function () {
          configuration.users["user1"] = [{
            domain: "home.example.com",
            policy: "allow",
            resources: [".*"]
          }];
          Assert(Authorizer.isAccessAllowed(
            {domain: "home.example.com", path: "/"}, "user1", ["group1"]));
          Assert(Authorizer.isAccessAllowed(
            {domain: "home.example.com", path: "/another/resource"}, "user1", ["group1"]));
          Assert(!Authorizer.isAccessAllowed(
            {domain: "another.home.example.com", path: "/"}, "user1", ["group1"]));
        });

        it("should deny to other users", function () {
          configuration.users["user1"] = [{
            domain: "home.example.com",
            policy: "allow",
            resources: [".*"]
          }];
          Assert(!Authorizer.isAccessAllowed(
            {domain: "home.example.com", path: "/"}, "user2", ["group1"]));
          Assert(!Authorizer.isAccessAllowed(
            {domain: "home.example.com", path: "/another/resource"}, "user2", ["group1"]));
          Assert(!Authorizer.isAccessAllowed(
            {domain: "another.home.example.com", path: "/"}, "user2", ["group1"]));
        });

        it("should allow user access only to specific resources", function () {
          configuration.users["user1"] = [{
            domain: "home.example.com",
            policy: "allow",
            resources: ["/private/.*", "^/begin", "/end$"]
          }];
          Assert(!Authorizer.isAccessAllowed(
            {domain: "home.example.com", path: "/"}, "user1", ["group1"]));
          Assert(!Authorizer.isAccessAllowed(
            {domain: "home.example.com", path: "/private"}, "user1", ["group1"]));
          Assert(Authorizer.isAccessAllowed(
            {domain: "home.example.com", path: "/private/class"}, "user1", ["group1"]));
          Assert(Authorizer.isAccessAllowed(
            {domain: "home.example.com", path: "/middle/private/class"}, "user1", ["group1"]));

          Assert(Authorizer.isAccessAllowed(
            {domain: "home.example.com", path: "/begin"}, "user1", ["group1"]));
          Assert(!Authorizer.isAccessAllowed(
            {domain: "home.example.com", path: "/not/begin"}, "user1", ["group1"]));

          Assert(Authorizer.isAccessAllowed(
            {domain: "home.example.com", path: "/abc/end"}, "user1", ["group1"]));
          Assert(!Authorizer.isAccessAllowed(
            {domain: "home.example.com", path: "/abc/end/x"}, "user1", ["group1"]));
        });

        it("should allow access to multiple domains", function () {
          configuration.users["user1"] = [{
            domain: "home.example.com",
            policy: "allow",
            resources: [".*"]
          }, {
            domain: "home1.example.com",
            policy: "allow",
            resources: [".*"]
          }, {
            domain: "home2.example.com",
            policy: "deny",
            resources: [".*"]
          }];
          Assert(Authorizer.isAccessAllowed(
            {domain: "home.example.com", path: "/"}, "user1", ["group1"]));
          Assert(Authorizer.isAccessAllowed(
            {domain: "home1.example.com", path: "/"}, "user1", ["group1"]));
          Assert(!Authorizer.isAccessAllowed(
            {domain: "home2.example.com", path: "/"}, "user1", ["group1"]));
          Assert(!Authorizer.isAccessAllowed(
            {domain: "home3.example.com", path: "/"}, "user1", ["group1"]));
        });

        it("should always apply latest rule", function () {
          configuration.users["user1"] = [{
            domain: "home.example.com",
            policy: "allow",
            resources: ["^/my/.*"]
          }, {
            domain: "home.example.com",
            policy: "deny",
            resources: ["^/my/private/.*"]
          }, {
            domain: "home.example.com",
            policy: "allow",
            resources: ["/my/private/resource"]
          }];

          Assert(Authorizer.isAccessAllowed(
            {domain: "home.example.com", path: "/my/poney"}, "user1", ["group1"]));
          Assert(!Authorizer.isAccessAllowed(
            {domain: "home.example.com", path: "/my/private/duck"}, "user1", ["group1"]));
          Assert(Authorizer.isAccessAllowed(
            {domain: "home.example.com", path: "/my/private/resource"}, "user1", ["group1"]));
        });
      });

      describe("check group rules", function () {
        it("should allow access when user is in group having a matching allowing rule", function () {
          configuration.groups["group1"] = [{
            domain: "home.example.com",
            policy: "allow",
            resources: ["^/$"]
          }];
          configuration.groups["group2"] = [{
            domain: "home.example.com",
            policy: "allow",
            resources: ["^/test$"]
          }, {
            domain: "home.example.com",
            policy: "deny",
            resources: ["^/private$"]
          }];
          Assert(Authorizer.isAccessAllowed(
            {domain: "home.example.com", path: "/"}, "user1", ["group1", "group2", "group3"]));
          Assert(Authorizer.isAccessAllowed(
            {domain: "home.example.com", path: "/test"}, "user1", ["group1", "group2", "group3"]));
          Assert(!Authorizer.isAccessAllowed(
            {domain: "home.example.com", path: "/private"}, "user1", ["group1", "group2", "group3"]));
          Assert(!Authorizer.isAccessAllowed(
            {domain: "another.home.example.com", path: "/"}, "user1", ["group1", "group2", "group3"]));
        });
      });
    });

    describe("check any rules", function () {
      it("should control access when any rules are defined", function () {
        configuration.any = [{
          domain: "home.example.com",
          policy: "allow",
          resources: ["^/public$"]
        }, {
          domain: "home.example.com",
          policy: "deny",
          resources: ["^/private$"]
        }];
        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/public"}, "user1", ["group1", "group2", "group3"]));
        Assert(!Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/private"}, "user1", ["group1", "group2", "group3"]));
        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/public"}, "user4", ["group5"]));
        Assert(!Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/private"}, "user4", ["group5"]));
      });
    });

    describe("check access control with default policy to allow", function () {
      beforeEach(function () {
        configuration.default_policy = "allow";
      });

      it("should allow access to anything when no rule is provided", function () {
        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/"}, "user1", ["group1"]));
        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/test"}, "user1", ["group1"]));
        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/dev"}, "user1", ["group1"]));
      });

      it("should deny access to one resource when defined", function () {
        configuration.users["user1"] = [{
          domain: "home.example.com",
          policy: "deny",
          resources: ["/test"]
        }];
        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/"}, "user1", ["group1"]));
        Assert(!Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/test"}, "user1", ["group1"]));
        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/dev"}, "user1", ["group1"]));
      });
    });

    describe("check access control with complete use case", function () {
      beforeEach(function () {
        configuration.default_policy = "deny";
      });

      it("should control access of multiple user (real use case)", function () {
        // Let say we have three users: admin, john, harry.
        // admin is in groups ["admins"]
        // john is in groups ["dev", "admin-private"]
        // harry is in groups ["dev"]
        configuration.any = [{
          domain: "home.example.com",
          policy: "allow",
          resources: ["^/public$", "^/$"]
        }];
        configuration.groups["dev"] = [{
          domain: "home.example.com",
          policy: "allow",
          resources: ["^/dev/?.*$"]
        }];
        configuration.groups["admins"] = [{
          domain: "home.example.com",
          policy: "allow",
          resources: [".*"]
        }];
        configuration.groups["admin-private"] = [{
          domain: "home.example.com",
          policy: "allow",
          resources: ["^/private/?.*"]
        }];
        configuration.users["john"] = [{
          domain: "home.example.com",
          policy: "allow",
          resources: ["^/private/john$"]
        }];
        configuration.users["harry"] = [{
          domain: "home.example.com",
          policy: "allow",
          resources: ["^/private/harry"]
        }, {
          domain: "home.example.com",
          policy: "deny",
          resources: ["^/dev/b.*$"]
        }];

        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/"}, "admin", ["admins"]));
        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/public"}, "admin", ["admins"]));
        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/dev"}, "admin", ["admins"]));
        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/dev/bob"}, "admin", ["admins"]));
        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/admin"}, "admin", ["admins"]));
        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/private/josh"}, "admin", ["admins"]));
        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/private/john"}, "admin", ["admins"]));
        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/private/harry"}, "admin", ["admins"]));

        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/"}, "john", ["dev", "admin-private"]));
        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/public"}, "john", ["dev", "admin-private"]));
        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/dev"}, "john", ["dev", "admin-private"]));
        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/dev/bob"}, "john", ["dev", "admin-private"]));
        Assert(!Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/admin"}, "john", ["dev", "admin-private"]));
        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/private/josh"}, "john", ["dev", "admin-private"]));
        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/private/john"}, "john", ["dev", "admin-private"]));
        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/private/harry"}, "john", ["dev", "admin-private"]));

        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/"}, "harry", ["dev"]));
        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/public"}, "harry", ["dev"]));
        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/dev"}, "harry", ["dev"]));
        Assert(!Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/dev/bob"}, "harry", ["dev"]));
        Assert(!Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/admin"}, "harry", ["dev"]));
        Assert(!Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/private/josh"}, "harry", ["dev"]));
        Assert(!Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/private/john"}, "harry", ["dev"]));
        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/private/harry"}, "harry", ["dev"]));
      });

      it("should control access when allowed at group level and denied at user level", function () {
        configuration.groups["dev"] = [{
          domain: "home.example.com",
          policy: "allow",
          resources: ["^/dev/?.*$"]
        }];
        configuration.users["john"] = [{
          domain: "home.example.com",
          policy: "deny",
          resources: ["^/dev/bob$"]
        }];

        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/dev/john"}, "john", ["dev"]));
        Assert(!Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/dev/bob"}, "john", ["dev"]));
      });

      it("should control access when allowed at 'any' level and denied at user level", function () {
        configuration.any = [{
          domain: "home.example.com",
          policy: "allow",
          resources: ["^/dev/?.*$"]
        }];
        configuration.users["john"] = [{
          domain: "home.example.com",
          policy: "deny",
          resources: ["^/dev/bob$"]
        }];

        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/dev/john"}, "john", ["dev"]));
        Assert(!Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/dev/bob"}, "john", ["dev"]));
      });

      it("should control access when allowed at 'any' level and denied at group level", function () {
        configuration.any = [{
          domain: "home.example.com",
          policy: "allow",
          resources: ["^/dev/?.*$"]
        }];
        configuration.groups["dev"] = [{
          domain: "home.example.com",
          policy: "deny",
          resources: ["^/dev/bob$"]
        }];

        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/dev/john"}, "john", ["dev"]));
        Assert(!Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/dev/bob"}, "john", ["dev"]));
      });

      it("should respect rules precedence", function () {
        // the priority from least to most is 'default_policy', 'all', 'group', 'user'
        // and the first rules in each category as a lower priority than the latest.
        // You can think of it that way: they override themselves inside each category.
        configuration.any = [{
          domain: "home.example.com",
          policy: "allow",
          resources: ["^/dev/?.*$"]
        }];
        configuration.groups["dev"] = [{
          domain: "home.example.com",
          policy: "deny",
          resources: ["^/dev/bob$"]
        }];
        configuration.users["john"] = [{
          domain: "home.example.com",
          policy: "allow",
          resources: ["^/dev/?.*$"]
        }];

        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/dev/john"}, "john", ["dev"]));
        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/dev/bob"}, "john", ["dev"]));
      });
    });

    describe("check whitelist access control with complete use case", function () {
      beforeEach(function () {
        configuration.default_policy = "deny";
      });

      it("should control whitelist access when allowed at group level and denied at user level", function () {
        configuration.groups["dev"] = [{
          domain: "home.example.com",
          policy: "allow",
          whitelist_policy: "allow",
          resources: ["^/dev/?.*$"]
        }];
        configuration.users["john"] = [{
          domain: "home.example.com",
          policy: "deny",
          whitelist_policy: "deny",
          resources: ["^/dev/bob$"]
        }];

        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/dev/john"}, "john", ["dev"]));
        Assert(!Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/dev/bob"}, "john", ["dev"]));
      });

      it("should control whitelist access when allowed at 'any' level and denied at user level", function () {
        configuration.any = [{
          domain: "home.example.com",
          policy: "allow",
          whitelist_policy: "allow",
          resources: ["^/dev/?.*$"]
        }];
        configuration.users["john"] = [{
          domain: "home.example.com",
          policy: "deny",
          whitelist_policy: "deny",
          resources: ["^/dev/bob$"]
        }];

        Assert(Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/dev/john"}, "john", ["dev"]));
        Assert(!Authorizer.isAccessAllowed(
          {domain: "home.example.com", path: "/dev/bob"}, "john", ["dev"]));
      });
    });
  });
});