import { ACLConfiguration, ACLRule } from "../configuration/schema/AclConfiguration";
import { Winston } from "../../../types/Dependencies";
import { MultipleDomainMatcher } from "./MultipleDomainMatcher";
import { Resource } from "./Resource";
import { Level } from "../authentication/Level";
import { IAuthorizer } from "./IAuthorizer";
import { Subject } from "./Subject";

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

export class Authorizer implements IAuthorizer {
  private logger: Winston;

  constructor(logger_: Winston) {
    this.logger = logger_;
  }

  private isAccessAllowedInRules(rules: ACLRule[], level: Level): AccessReturn {
    if (!rules)
      return AccessReturn.NO_MATCHING_RULES;

    const policies = rules.map(r => r.policy);

    if (rules.length > 0) {
      if (policies[0] == "bypass") {
        return AccessReturn.GRANT_ACCESS;
      } else if (policies[0] == "one_factor" && level >= Level.FIRST_FACTOR) {
        return AccessReturn.GRANT_ACCESS;
      } else if (policies[0] == "two_factor" && level >= Level.SECOND_FACTOR) {
        return AccessReturn.GRANT_ACCESS;
      } else {
        return AccessReturn.DENY_ACCESS;
      }
    }
    return AccessReturn.NO_MATCHING_RULES;
  }

  private getMatchingUserRules(
    policy: ACLConfiguration,
    user: string,
    resource: Resource): ACLRule[] {

    const userRules = policy.users[user];
    if (!userRules) return [];
    return userRules
      .filter(MatchDomain(resource.domain))
      .filter(MatchResource(resource.path));
  }

  private getMatchingGroupRules(
    policy: ACLConfiguration,
    groups: string[],
    resource: Resource): ACLRule[] {

    const that = this;
    // There is no ordering between group rules. That is, when a user belongs to 2 groups, there is no
    // guarantee one set of rules has precedence on the other one.
    const groupRules = groups.reduce(function (rules: ACLRule[], group: string) {
      const groupRules = policy.groups[group];
      if (groupRules) rules = rules.concat(groupRules);
      return rules;
    }, []);
    return groupRules
      .filter(MatchDomain(resource.domain))
      .filter(MatchResource(resource.path));
  }

  private getMatchingAllRules(policy: ACLConfiguration, resource: Resource): ACLRule[] {
    const rules = policy.any;
    if (!rules) return [];
    return rules
      .filter(MatchDomain(resource.domain))
      .filter(MatchResource(resource.path));
  }

  private isAccessAllowedDefaultPolicy(default_policy: string, level: Level): boolean {
    return default_policy == "bypass" ||
      (default_policy == "one_factor" && level >= Level.FIRST_FACTOR) ||
      (default_policy == "two_factor" && level >= Level.SECOND_FACTOR);
  }

  /**
   * Check if a user has access to the given resource.
   *
   * @param resource The resource to check permissions for.
   * @param user  The subject to check permissions for.
   * @return true if the user has access, false otherwise.
   */
  isAccessAllowed(policy: ACLConfiguration, resource: Resource, subject: Subject): boolean {
    if (!policy) return true;

    const allRules = this.getMatchingAllRules(policy, resource);
    const groupRules = this.getMatchingGroupRules(policy, subject.groups, resource);
    const userRules = this.getMatchingUserRules(policy, subject.user, resource);
    const rules = allRules.concat(groupRules).concat(userRules).reverse();

    const access = this.isAccessAllowedInRules(rules, subject.level);
    if (access == AccessReturn.GRANT_ACCESS)
      return true;
    else if (access == AccessReturn.DENY_ACCESS)
      return false;

    return this.isAccessAllowedDefaultPolicy(policy.default_policy, subject.level);
  }
}