import { ACLConfiguration, complete as AclConfigurationComplete } from "./AclConfiguration";
import { AuthenticationMethodsConfiguration, complete as AuthenticationMethodsConfigurationComplete } from "./AuthenticationMethodsConfiguration";
import { AuthenticationBackendConfiguration, complete as AuthenticationBackendComplete } from "./AuthenticationBackendConfiguration";
import { NotifierConfiguration, complete as NotifierConfigurationComplete } from "./NotifierConfiguration";
import { RegulationConfiguration, complete as RegulationConfigurationComplete } from "./RegulationConfiguration";
import { SessionConfiguration, complete as SessionConfigurationComplete } from "./SessionConfiguration";
import { StorageConfiguration, complete as StorageConfigurationComplete } from "./StorageConfiguration";
import { TotpConfiguration, complete as TotpConfigurationComplete } from "./TotpConfiguration";
import { NetworkBindingConfiguration, complete as NetworkBindingConfigurationComplete } from "./NetworkBindingConfiguration";

export interface Configuration {
  // Default ACLs when user is not recognized by IP.
  access_control?: ACLConfiguration;

  // Configuration binding users to IP/CIDR. It allows to automatically
  // recognize the user by IP. This allow to bypass some security gates
  // sometimes.
  network_binding?: NetworkBindingConfiguration;
  // The policy to apply when the IP of the user is known.
  network_access_control?: ACLConfiguration;

  authentication_backend: AuthenticationBackendConfiguration;

  default_redirection_url?: string;
  logs_level?: string;
  notifier?: NotifierConfiguration;
  port?: number;
  regulation?: RegulationConfiguration;
  session?: SessionConfiguration;
  storage?: StorageConfiguration;
  totp?: TotpConfiguration;
}

export function complete(
  configuration: Configuration):
  [Configuration, string[]] {

  const newConfiguration: Configuration = JSON.parse(
    JSON.stringify(configuration));
  const errors: string[] = [];

  newConfiguration.access_control =
    AclConfigurationComplete(
      newConfiguration.access_control);

  newConfiguration.network_binding =
    NetworkBindingConfigurationComplete(
      newConfiguration.network_binding);

  newConfiguration.network_access_control =
    AclConfigurationComplete(newConfiguration.network_access_control);

  const [backend, backendError] =
    AuthenticationBackendComplete(
      newConfiguration.authentication_backend);
  if (backendError) errors.push(backendError);
  newConfiguration.authentication_backend = backend;

  if (!newConfiguration.logs_level) {
    newConfiguration.logs_level = "info";
  }

  const [notifier, notifierError] =
    NotifierConfigurationComplete(
      newConfiguration.notifier);
  if (notifierError) errors.push(notifierError);
  newConfiguration.notifier = notifier;

  if (!newConfiguration.port) {
    newConfiguration.port = 8080;
  }

  newConfiguration.regulation = RegulationConfigurationComplete(
    newConfiguration.regulation);
  newConfiguration.session = SessionConfigurationComplete(
    newConfiguration.session);
  newConfiguration.storage = StorageConfigurationComplete(
    newConfiguration.storage);
  newConfiguration.totp = TotpConfigurationComplete(
    newConfiguration.totp);

  return [newConfiguration, errors];
}