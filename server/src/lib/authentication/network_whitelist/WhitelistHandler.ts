import { AuthenticationSession } from "../../../../types/AuthenticationSession";
import { AuthenticationSessionHandler } from "../../AuthenticationSessionHandler";
import { IWhitelistHandler } from "./IWhitelistHandler";
import { IUsersDatabase } from "../backends/IUsersDatabase";
import { ServerVariables } from "../../ServerVariables";
import Constants = require("../../../../../shared/constants");
import Bluebird = require("bluebird");
import express = require("express");
import IpRangeCheck = require("ip-range-check");
import { NetworkBindingConfiguration } from "../../configuration/schema/NetworkBindingConfiguration";

export class WhitelistHandler implements IWhitelistHandler {
  private configuration: NetworkBindingConfiguration;

  constructor(configuration: NetworkBindingConfiguration) {
    this.configuration = configuration;
  }

  getUserByIp(ip: string): Bluebird<string> {
    const users = Object.keys(this.configuration)
      .filter(cidr => IpRangeCheck(ip, cidr))
      .map(key => this.configuration[key]);

    if (users.length == 0) return Bluebird.resolve(undefined);

    return Bluebird.resolve(users[0]);
  }
}