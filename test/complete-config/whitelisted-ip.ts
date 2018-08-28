require("chromedriver");
import Bluebird = require("bluebird");
import SeleniumWebdriver = require("selenium-webdriver");
import WithDriver from '../helpers/with-driver';
import VisitPage from '../helpers/visit-page';
import WaitRedirected from '../helpers/wait-redirected';
import ISeeTextInPage from '../helpers/i-see-text-in-page';

describe.only("Whitelisted IP can cannoct without authenticating", function() {
  this.timeout(20000);
  WithDriver();

  // Client 1 is whitelisted.
  it("should be able to login without authenticating.", function() {
    const that = this;
    return VisitPage(that.driver, "https://admin.example.com:8081/secret.html")
      .then(() => ISeeTextInPage(that.driver, "This is a very important secret!"));
  });

  // Client 2 is not whitelisted.
  it("should not be able to login without authenticating.", function() {
    const that = this;
    return VisitPage(that.driver, "https://admin.example.com:8082/secret.html")
      .then(() => WaitRedirected(that.driver, "https://login.example.com:8080/?rd=https://admin.example.com:8082/secret.html"));
  });
});
