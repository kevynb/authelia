import Express = require("express");
import Bluebird = require("bluebird");
import Util = require("util");
import Exceptions = require("../../Exceptions");
import { ServerVariables } from "../../ServerVariables";
import { Resource } from "../../authorizations/Resource";
import { Level } from "../../authentication/Level";
import { Subject } from "../../authorizations/Subject";
import { ACLConfiguration } from "../../configuration/schema/AclConfiguration";

export default function (
  req: Express.Request,
  policy: ACLConfiguration,
  resource: Resource,
  subject: Subject,
  vars: ServerVariables): Bluebird<undefined> {

  return new Bluebird(function (resolve, reject) {
    const isAllowed = vars.authorizer
      .isAccessAllowed(policy, resource, subject);

    if (!isAllowed) {
      reject(new Exceptions.AccessDeniedError(Util.format(
        "Access denied to '%s/%s' for user '%s'",
        resource.domain, resource.path, subject.user)));
    }
    resolve();
  });
}