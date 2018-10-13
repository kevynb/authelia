
import express = require("express");
import objectPath = require("object-path");
import Endpoints = require("../../../../../shared/api");
import BluebirdPromise = require("bluebird");
import { AuthenticationSession } from "../../../../types/AuthenticationSession";
import { AuthenticationSessionHandler } from "../../AuthenticationSessionHandler";
import Constants = require("../../../../../shared/constants");
import Endpoint = require("../../../../../shared/api");
import Util = require("util");
import { ServerVariables } from "../../ServerVariables";
import { Level } from "../../authentication/Level";
import { getRedirectParam } from "../helpers";

function redirectToSecondFactorPage(req: express.Request, res: express.Response) {
  const redirectUrl = getRedirectParam(req);
  if (!redirectUrl)
    res.redirect(Endpoints.SECOND_FACTOR_GET);
  else
    res.redirect(Util.format("%s?%s=%s", Endpoints.SECOND_FACTOR_GET,
      Constants.REDIRECT_QUERY_PARAM,
      redirectUrl));
}

function redirectToService(req: express.Request, res: express.Response) {
  const redirectUrl = getRedirectParam(req);
  if (!redirectUrl)
    res.redirect(Endpoints.LOGGED_IN);
  else
    res.redirect(redirectUrl);
}

function renderFirstFactor(res: express.Response) {
  res.render("firstfactor", {
    first_factor_post_endpoint: Endpoints.FIRST_FACTOR_POST,
    reset_password_request_endpoint: Endpoints.RESET_PASSWORD_REQUEST_GET
  });
}

function redirect(req: express.Request, res: express.Response, authSession: AuthenticationSession) {
  if (authSession.authentication_level == Level.FIRST_FACTOR) {
    redirectToSecondFactorPage(req, res);
  } else {
    renderFirstFactor(res);
  }
}

export default function (vars: ServerVariables) {
  return function (req: express.Request, res: express.Response): BluebirdPromise<void> {
    return new BluebirdPromise(function (resolve, reject) {
      const authSession = AuthenticationSessionHandler.get(req, vars.logger);
      return redirect(req, res, authSession);
    });
  };
}
