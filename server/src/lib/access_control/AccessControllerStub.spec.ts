import Sinon = require("sinon");
import { IAccessController } from "./IAccessController";
import { Resource } from "./Resource";

export class AccessControllerStub implements IAccessController {
  isAccessAllowedMock: Sinon.SinonStub;

  constructor() {
    this.isAccessAllowedMock = Sinon.stub();
  }

  isAccessAllowed(resource: Resource, user: string, groups: string[]): boolean {
    return this.isAccessAllowedMock(resource, user, groups);
  }
}
