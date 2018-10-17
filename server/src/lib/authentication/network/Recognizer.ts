import { AuthenticationSession } from "../../../../types/AuthenticationSession";
import { AuthenticationSessionHandler } from "../../AuthenticationSessionHandler";
import { IUsersDatabase } from "../backends/IUsersDatabase";
import { ServerVariables } from "../../ServerVariables";
import Constants = require("../../../../../shared/constants");
import Bluebird = require("bluebird");
import express = require("express");
import IpRangeCheck = require("ip-range-check");
import { NetworkBindingConfiguration } from "../../configuration/schema/NetworkBindingConfiguration";
import { IRecognizer } from "./IRecognizer";
import { NetworkBindingCache } from "./NetworkBindingCache";

export class Recognizer implements IRecognizer {
  private cache: NetworkBindingCache;

  constructor(cache: NetworkBindingCache) {
    this.cache = cache;
  }

  recognize(ip: string): string {
    const users = Object.keys(this.cache)
      .filter(cidr => IpRangeCheck(ip, cidr))
      .map(key => this.cache[key]);

    if (users.length == 0) return;
    return users[0];
  }
}