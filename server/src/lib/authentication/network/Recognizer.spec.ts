import Sinon = require("sinon");
import Bluebird = require("bluebird");
import express = require("express");
import { IUsersDatabase } from "../backends/IUsersDatabase";
import { ServerVariables } from "../../ServerVariables";
import { IRecognizer } from "./IRecognizer";

export class RecognizerStub implements IRecognizer {
  recognizeStub: Sinon.SinonStub;

  constructor() {
    this.recognizeStub = Sinon.stub();
  }

  recognize(ip: string): string {
    return this.recognizeStub(ip);
  }
}