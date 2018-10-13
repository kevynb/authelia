import { IUsersDatabase } from "../backends/IUsersDatabase";
import Bluebird = require("bluebird");
import express = require("express");
import { ServerVariables } from "../../ServerVariables";

export interface IWhitelistHandler {
  getUserByIp(ip: string): Bluebird<string>;
}