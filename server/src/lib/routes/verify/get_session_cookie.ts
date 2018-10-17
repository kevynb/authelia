import Express = require("express");
import BluebirdPromise = require("bluebird");
import Util = require("util");
import ObjectPath = require("object-path");

import Exceptions = require("../../Exceptions");
import { Configuration } from "../../configuration/schema/Configuration";
import Constants = require("../../../../../shared/constants");
import { DomainExtractor } from "../../utils/DomainExtractor";
import { ServerVariables } from "../../ServerVariables";
import { IRequestLogger } from "../../logging/IRequestLogger";
import { AuthenticationSession } from "../../../../types/AuthenticationSession";
import { AuthenticationSessionHandler } from "../../AuthenticationSessionHandler";
import AccessControl from "./access_control";
import { Level } from "../../authentication/Level";
import { Merger } from "../../authorizations/Merger";

const FIRST_FACTOR_NOT_VALIDATED_MESSAGE = "First factor not yet validated";
const SECOND_FACTOR_NOT_VALIDATED_MESSAGE = "Second factor not yet validated";

function verify_inactivity(req: Express.Request,
  authSession: AuthenticationSession,
  configuration: Configuration, logger: IRequestLogger)
  : BluebirdPromise<void> {

  // If inactivity is not specified, then inactivity timeout does not apply
  if (!configuration.session.inactivity) {
    return BluebirdPromise.resolve();
  }

  const lastActivityTime = authSession.last_activity_datetime;
  const currentTime = new Date().getTime();
  authSession.last_activity_datetime = currentTime;

  const inactivityPeriodMs = currentTime - lastActivityTime;
  logger.debug(req, "Inactivity period was %s s and max period was %s.",
    inactivityPeriodMs / 1000, configuration.session.inactivity / 1000);
  if (inactivityPeriodMs < configuration.session.inactivity) {
    return BluebirdPromise.resolve();
  }

  logger.debug(req, "Session has been reset after too long inactivity period.");
  AuthenticationSessionHandler.reset(req, logger);
  return BluebirdPromise.reject(new Error("Inactivity period exceeded."));
}

export default function (req: Express.Request, res: Express.Response,
  vars: ServerVariables, authSession: AuthenticationSession)
  : BluebirdPromise<{ username: string, groups: string[] }> {
  return BluebirdPromise.resolve()
    .then(() => {

      // TODO: validate a challenge to avoid IP spoofing.
      const recognizedUserId = vars.networkRecognizer.recognize(req.ip);
      if (recognizedUserId) {
        vars.logger.debug(req, "User %s is recognized by IP.", authSession.userid);
        authSession.userid = recognizedUserId;
      } else if (!recognizedUserId) {
        if (!authSession.userid) {
          // Redirect to portal because user is not authenticate and not
          // recognized from IP.
          return BluebirdPromise.reject(new Exceptions.NotAuthenticatedError(
            "User is not authenticated."));
        } else {
          vars.logger.debug(req, "User %s is authenticated but not recognized by IP.",
            authSession.userid);
        }
      }

      const originalUrl = ObjectPath.get<Express.Request, string>(req, "headers.x-original-url");
      const originalUri =
        ObjectPath.get<Express.Request, string>(req, "headers.x-original-uri");

      const domain = DomainExtractor.fromUrl(originalUrl);
      vars.logger.debug(req, "domain=%s, request_uri=%s, user=%s, groups=%s", domain,
        originalUri, authSession.userid, authSession.groups.join(","));

      const resource = {domain, path: originalUri};
      const subject = {
        user: authSession.userid,
        groups: authSession.groups,
        level: authSession.authentication_level
      };
      const policy = (recognizedUserId)
        ? Merger.merge(vars.config.access_control, vars.config.network_access_control)
        : vars.config.access_control;
      return AccessControl(req, policy, resource, subject, vars);
    })
    .then(function () {
      return verify_inactivity(req, authSession,
        vars.config, vars.logger);
    })
    .then(function () {
      return BluebirdPromise.resolve({
        username: authSession.userid,
        groups: authSession.groups
      });
    });
}