import { ACLConfiguration, ACLRule } from "../configuration/schema/AclConfiguration";
import { IAccessController } from "./IAccessController";
import { Winston } from "../../../types/Dependencies";
import { MultipleDomainMatcher } from "./MultipleDomainMatcher";
import { Resource } from "./Resource";
import { Identity } from "./Identity";
import { Level } from "../authentication/Level";

enum AccessReturn {
  NO_MATCHING_RULES,
  GRANT_ACCESS,
  DENY_ACCESS
}

function MatchDomain(actualDomain: string) {
  return function (rule: ACLRule): boolean {
    return MultipleDomainMatcher.match(actualDomain, rule.domain);
  };
}

function MatchResource(actualResource: string) {
  return function (rule: ACLRule): boolean {
    // If resources key is not provided, the rule applies to all resources.
    if (!rule.resources) return true;

    for (let i = 0; i < rule.resources.length; ++i) {
      const regexp = new RegExp(rule.resources[i]);
      if (regexp.test(actualResource)) return true;
    }
    return false;
  };
}

export class AccessController implements IAccessController {
  private logger: Winston;
  private readonly configuration: ACLConfiguration;

  constructor(configuration: ACLConfiguration, logger_: Winston) {
    this.logger = logger_;
    this.configuration = configuration;
  }

  private isAccessAllowedInRules(rules: ACLRule[], level: Level): AccessReturn {
    if (!rules)
      return AccessReturn.NO_MATCHING_RULES;

    const policies = rules.map(r => r.policy);

    if (rules.length > 0) {
      if (policies[0] == "bypass") {
        return AccessReturn.GRANT_ACCESS;
      } else if (policies[0] == "first_factor" && level >= Level.FIRST_FACTOR) {
        return AccessReturn.GRANT_ACCESS;
      } else if (policies[0] == "second_factor" && level >= Level.SECOND_FACTOR) {
        return AccessReturn.GRANT_ACCESS;
      } else {
        return AccessReturn.DENY_ACCESS;
      }
    }
    return AccessReturn.NO_MATCHING_RULES;
  }

  private getMatchingUserRules(user: string, resource: Resource): ACLRule[] {
    const userRules = this.configuration.users[user];
    if (!userRules) return [];
    return userRules
      .filter(MatchDomain(resource.domain))
      .filter(MatchResource(resource.path));
  }

  private getMatchingGroupRules(groups: string[], resource: Resource): ACLRule[] {
    const that = this;
    // There is no ordering between group rules. That is, when a user belongs to 2 groups, there is no
    // guarantee one set of rules has precedence on the other one.
    const groupRules = groups.reduce(function (rules: ACLRule[], group: string) {
      const groupRules = that.configuration.groups[group];
      if (groupRules) rules = rules.concat(groupRules);
      return rules;
    }, []);
    return groupRules
      .filter(MatchDomain(resource.domain))
      .filter(MatchResource(resource.path));
  }

  private getMatchingAllRules(resource: Resource): ACLRule[] {
    const rules = this.configuration.any;
    if (!rules) return [];
    return rules
      .filter(MatchDomain(resource.domain))
      .filter(MatchResource(resource.path));
  }

  private isAccessAllowedDefaultPolicy(level: Level): boolean {
    return this.configuration.default_policy == "bypass" ||
      (this.configuration.default_policy == "first_factor" && level >= Level.FIRST_FACTOR) ||
      (this.configuration.default_policy == "second_factor" && level >= Level.SECOND_FACTOR);
  }

  /**
   * Check if a user has access to the given resource.
   *
   * @param resource The resource to check permissions for.
   * @param user  The user to check permissions for.
   * @param groups The groups of the user to check permissions for.
   * @return true if the user has access, false otherwise.
   */
  isAccessAllowed(resource: Resource, identity: Identity, level: Level): boolean {
    if (!this.configuration) return true;

    const allRules = this.getMatchingAllRules(resource);
    const groupRules = this.getMatchingGroupRules(identity.groups, resource);
    const userRules = this.getMatchingUserRules(identity.user, resource);
    const rules = allRules.concat(groupRules).concat(userRules).reverse();

    const access = this.isAccessAllowedInRules(rules, level);
    if (access == AccessReturn.GRANT_ACCESS)
      return true;
    else if (access == AccessReturn.DENY_ACCESS)
      return false;

    return this.isAccessAllowedDefaultPolicy(level);
  }
}