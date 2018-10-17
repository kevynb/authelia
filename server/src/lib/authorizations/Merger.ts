import { ACLConfiguration } from "../configuration/schema/AclConfiguration";

export class Merger {
  static merge(policy1: ACLConfiguration, policy2: ACLConfiguration) {
    const newPolicy: ACLConfiguration = {
      default_policy: policy2.default_policy,
      any: [],
      groups: {},
      users: {}
    };

    newPolicy.default_policy = policy2.default_policy;

    newPolicy.any = policy1.any.concat(policy2.any);

    Object.keys(policy1.groups).forEach(group => {
      newPolicy.groups[group] = policy1.groups[group];
      if (group in policy2.groups) {
        newPolicy.groups[group] = newPolicy.groups[group]
          .concat(policy2.groups[group]);
      }
    });

    Object.keys(policy1.users).forEach(user => {
      newPolicy.users[user] = policy1.users[user];
      if (user in policy2.users) {
        newPolicy.users[user] = newPolicy.users[user]
          .concat(policy2.users[user]);
      }
    });
    console.log(JSON.stringify(newPolicy));
    return newPolicy;
  }
}