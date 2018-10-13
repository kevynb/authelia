import Util = require("util");

export interface NetworkBindingConfiguration {
  [cidr: string]: string;
}

export function complete(configuration: NetworkBindingConfiguration): NetworkBindingConfiguration {
  const newConfiguration: NetworkBindingConfiguration = (configuration)
    ? JSON.parse(JSON.stringify(configuration))
    : {};

  return newConfiguration;
}