import { Resource } from "./Resource";
import { Identity } from "./Identity";
import { Level } from "../authentication/Level";

export interface IAccessController {
  isAccessAllowed(resource: Resource, identity: Identity, level: Level): boolean;
}