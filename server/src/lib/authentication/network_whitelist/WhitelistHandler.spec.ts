import Sinon = require("sinon");
import Bluebird = require("bluebird");
import express = require("express");
import { IWhitelistHandler } from "./IWhitelistHandler";
import { IUsersDatabase } from "../backends/IUsersDatabase";
import { ServerVariables } from "../../ServerVariables";

export class WhitelistHandlerStub implements IWhitelistHandler {
  isWhitelistedStub: Sinon.SinonStub;

  constructor() {
    this.isWhitelistedStub = Sinon.stub();
  }

  getUserByIp(ip: string): Bluebird<string> {
    return this.isWhitelistedStub(ip);
  }
}