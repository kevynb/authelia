
import Express = require("express");
import Endpoints = require("../../../../../shared/api");
import BluebirdPromise = require("bluebird");
import { AuthenticationSessionHandler } from "../../AuthenticationSessionHandler";
import { ServerVariables } from "../../ServerVariables";
import { Level } from "../../authentication/Level";
import { getRedirectParam } from "../helpers";

const TEMPLATE_NAME = "secondfactor";

export default function (vars: ServerVariables) {
  function handler(req: Express.Request, res: Express.Response)
    : BluebirdPromise<void> {

    return new BluebirdPromise(function (resolve, reject) {
      const authSession = AuthenticationSessionHandler.get(req, vars.logger);

      if (authSession.authentication_level == Level.NOT_AUTHENTICATED) {
        res.redirect(Endpoints.FIRST_FACTOR_GET);
        return;
      } else if (authSession.authentication_level == Level.SECOND_FACTOR) {
        const redirectUrl = getRedirectParam(req);
        if (redirectUrl) {
          res.redirect(redirectUrl);
        } else if (vars.config.default_redirection_url) {
          res.redirect(vars.config.default_redirection_url);
        } else {
          res.redirect(Endpoints.LOGGED_IN);
        }
        resolve();
        return;
      }

      res.render(TEMPLATE_NAME, {
        username: authSession.userid,
        totp_identity_start_endpoint:
        Endpoints.SECOND_FACTOR_TOTP_IDENTITY_START_GET,
        u2f_identity_start_endpoint:
        Endpoints.SECOND_FACTOR_U2F_IDENTITY_START_GET
      });
      resolve();
    });
  }
  return handler;
}
