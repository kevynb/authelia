import Sinon = require("sinon");
import { IAuthorizer } from "./IAuthorizer";
import { Resource } from "./Resource";
import { Subject } from "./Subject";
import { ACLConfiguration } from "../configuration/schema/AclConfiguration";

export class AuthorizerStub implements IAuthorizer {
  isAccessAllowedMock: Sinon.SinonStub;

  constructor() {
    this.isAccessAllowedMock = Sinon.stub();
  }

  isAccessAllowed(policy: ACLConfiguration, resource: Resource, subject: Subject): boolean {
    return this.isAccessAllowedMock(policy, resource, subject);
  }
}
