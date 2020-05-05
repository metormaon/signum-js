const {Builder, By, Key, until} = require('selenium-webdriver');
const chrome = require('selenium-webdriver/chrome');

describe("submitLogin", function() {
    it("should fail without username", async function () {
        let driver = await new Builder()
            .forBrowser('chrome')
            .setChromeOptions(new chrome.Options().headless().windowSize({width: 1920, height: 1080}))
            .build();

        try {
            await driver.get("file://" + __dirname + "test.html");

            await expectAsync(
                driver.executeScript("window.executeLogin();")
            ).toBeRejectedWithError("Username is null or empty");
        } finally {
            await driver.quit();
        }
    });
});


