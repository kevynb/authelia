import Express = require("express");
import Bluebird = require("bluebird");
import Util = require("util");
import Exceptions = require("../../Exceptions");
import { ServerVariables } from "../../ServerVariables";
import { Resource } from "../../access_control/Resource";
import { Identity } from "../../access_control/Identity";
import { Level } from "../../authentication/Level";

export default function (
  req: Express.Request,
  resource: Resource,
  identity: Identity,
  level: Level,
  vars: ServerVariables): Bluebird<undefined> {

  return new Bluebird(function (resolve, reject) {
    const isAllowed = vars.accessController
      .isAccessAllowed(resource, identity, level);

    if (!isAllowed) {
      reject(new Exceptions.AccessDeniedError(Util.format(
        "Access denied to '%s/%s' for user '%s'", identity.user, resource.domain, resource.path)));
    }
    resolve();
  });
}