import Express = require("express");
import Constants = require("../../../../shared/constants");

export function getRedirectParam(req: Express.Request) {
  return req.query[Constants.REDIRECT_QUERY_PARAM] != "undefined"
    ? req.query[Constants.REDIRECT_QUERY_PARAM]
    : undefined;
}