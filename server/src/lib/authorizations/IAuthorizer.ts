import { Resource } from "./Resource";
import { Level } from "../authentication/Level";
import { Subject } from "./Subject";
import { ACLConfiguration } from "../configuration/schema/AclConfiguration";

export interface IAuthorizer {
  isAccessAllowed(policy: ACLConfiguration, resource: Resource, subject: Subject): boolean;
}