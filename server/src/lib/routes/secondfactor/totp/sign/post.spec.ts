
import BluebirdPromise = require("bluebird");
import Sinon = require("sinon");
import Assert = require("assert");
import Exceptions = require("../../../../Exceptions");
import { AuthenticationSessionHandler } from "../../../../AuthenticationSessionHandler";
import { AuthenticationSession } from "../../../../../../types/AuthenticationSession";
import SignPost = require("./post");
import { ServerVariables } from "../../../../ServerVariables";

import ExpressMock = require("../../../../stubs/express.spec");
import { UserDataStoreStub } from "../../../../storage/UserDataStoreStub.spec";
import { ServerVariablesMock, ServerVariablesMockBuilder } from "../../../../ServerVariablesMockBuilder.spec";
import { Level } from "../../../../authentication/Level";

describe("routes/secondfactor/totp/sign/post", function () {
  let req: ExpressMock.RequestMock;
  let res: ExpressMock.ResponseMock;
  let authSession: AuthenticationSession;
  let vars: ServerVariables;
  let mocks: ServerVariablesMock;

  beforeEach(function () {
    const s = ServerVariablesMockBuilder.build();
    vars = s.variables;
    mocks = s.mocks;
    const app_get = Sinon.stub();
    req = {
      originalUrl: "/api/totp-register",
      app: {},
      body: {
        token: "abc"
      },
      session: {},
      query: {
        redirect: "http://redirect"
      }
    };
    res = ExpressMock.ResponseMock();

    const doc = {
      userid: "user",
      secret: {
        base32: "ABCDEF"
      }
    };
    mocks.userDataStore.retrieveTOTPSecretStub.returns(BluebirdPromise.resolve(doc));
    authSession = AuthenticationSessionHandler.get(req as any, vars.logger);
    authSession.userid = "user";
    authSession.authentication_level = Level.ONE_FACTOR;
  });


  it("should send status code 200 when totp is valid", function () {
    mocks.totpHandler.validateStub.returns(true);
    return SignPost.default(vars)(req as any, res as any)
      .then(function () {
        Assert.equal(authSession.authentication_level, Level.TWO_FACTOR);
        return BluebirdPromise.resolve();
      });
  });

  it("should send error message when totp is not valid", function () {
    mocks.totpHandler.validateStub.returns(false);
    return SignPost.default(vars)(req as any, res as any)
      .then(function () {
        Assert.notEqual(authSession.authentication_level, Level.TWO_FACTOR);
        Assert.equal(res.status.getCall(0).args[0], 200);
        Assert.deepEqual(res.send.getCall(0).args[0], {
          error: "Operation failed."
        });
        return BluebirdPromise.resolve();
      });
  });
});

