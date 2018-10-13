import SecondFactorGet from "./get";
import { ServerVariablesMockBuilder, ServerVariablesMock }
  from "../../ServerVariablesMockBuilder.spec";
import { ServerVariables } from "../../ServerVariables";
import Sinon = require("sinon");
import ExpressMock = require("../../stubs/express.spec");
import Assert = require("assert");
import Endpoints = require("../../../../../shared/api");
import BluebirdPromise = require("bluebird");
import { Level } from "../../authentication/Level";

describe("routes/secondfactor/get", function () {
  let mocks: ServerVariablesMock;
  let vars: ServerVariables;
  let req: ExpressMock.RequestMock;
  let res: ExpressMock.ResponseMock;

  beforeEach(function () {
    const s = ServerVariablesMockBuilder.build();
    mocks = s.mocks;
    vars = s.variables;

    req = ExpressMock.RequestMock();
    res = ExpressMock.ResponseMock();

    req.session = {
      auth: {
        userid: "user",
        authentication_level: Level.FIRST_FACTOR
      }
    };
  });

  describe("test redirection", function () {
    describe("not authenticated", () => {
      it("should redirect to first factor page", function () {
        req.session.authentication_level = Level.NOT_AUTHENTICATED;
        return SecondFactorGet(vars)(req as any, res as any)
          .then(function () {
            Assert(res.redirect.calledWith(Endpoints.FIRST_FACTOR_GET));
            return BluebirdPromise.resolve();
          });
      });
    });

    describe("authenticated up to first factor", () => {
      it("should serve second factor page", () => {
        req.session.authentication_level = Level.FIRST_FACTOR;
        req.session.auth.second_factor = false;
        return SecondFactorGet(vars)(req as any, res as any)
          .then(function () {
            Assert(res.render.calledWith("secondfactor"));
            return BluebirdPromise.resolve();
          });
      });
    });

    describe("authenticated up to second factor", () => {
      describe("default redirection url is defined", () => {
        it("should redirect to default redirection url", () => {
          vars.config.default_redirection_url = "http://redirect";
          req.session.authentication_level = Level.SECOND_FACTOR;
          return SecondFactorGet(vars)(req as any, res as any)
            .then(function () {
              Assert(res.redirect.calledWith(vars.config.default_redirection_url));
              return BluebirdPromise.resolve();
            });
        });
      });
    });
  });
});