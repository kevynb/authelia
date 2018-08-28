import Bluebird = require("bluebird");
import SeleniumWebdriver = require("selenium-webdriver");

export default function(driver: any, text: string) {
  return driver.findElement(SeleniumWebdriver.By.tagName("body")).getText()
    .then((content: string) => {
      if (content.indexOf(text) > -1) {
        return Bluebird.resolve();
      }
      return Bluebird.reject(new Error("Text not found in page."));
    })
}