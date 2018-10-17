import { Level } from "../authentication/Level";

export interface Subject {
  user: string;
  groups: string[];
  level: Level;
}