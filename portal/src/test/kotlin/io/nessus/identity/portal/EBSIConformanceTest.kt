package io.nessus.identity.portal

import io.kotest.matchers.booleans.shouldBeTrue
import io.ktor.server.engine.EmbeddedServer
import io.nessus.identity.service.ConfigProvider
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.Max
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.openqa.selenium.By
import org.openqa.selenium.JavascriptExecutor
import org.openqa.selenium.WebDriver
import org.openqa.selenium.WebElement
import org.openqa.selenium.chrome.ChromeDriver
import org.openqa.selenium.chrome.ChromeOptions
import org.openqa.selenium.support.ui.WebDriverWait
import java.net.URI
import java.net.URLEncoder
import java.time.Duration

/**
 * brew install --cask google-chrome
 * brew install chromedriver
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EBSIConformanceTest : AbstractActionsTest() {

    lateinit var embeddedServer: EmbeddedServer<*, *>
    lateinit var driver: WebDriver

    @BeforeAll
    fun setup() {
        System.setProperty("webdriver.chrome.driver", "/opt/homebrew/bin/chromedriver")
        val options = ChromeOptions().apply {
            addArguments("--headless=new")
        }
        driver = ChromeDriver(options)
        driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(10))

        embeddedServer = PortalServer().createServer()
        embeddedServer.start(wait = false)

        prepareHolderTests()
    }

    @AfterAll
    fun tearDown() {
        driver.quit()
        embeddedServer.stop(3000, 10000)
    }

    fun nextStep(millis: Long = 1000) {
        Thread.sleep(millis)
    }

    @Test
    fun testCTWalletSameAuthorisedInTime() {

        val wait = WebDriverWait(driver, Duration.ofSeconds(10))
        val ctx = userLogin(Max)

        // Click the collapsible element
        driver.findElement(By.id("inTime-credential-same-device")).click()
        nextStep()

        // Click the "Initiate" link
        val mainTab = driver.windowHandle
        val ctType = "CTWalletSameAuthorisedInTime"
        val xpath = By.xpath("//a[contains(@href, 'credential_type=$ctType')]")
        fixupInitiateHref(ctx, driver.findElement(xpath)).click()
        nextStep()

        // Wait for the new window to open and switch to it
        wait.until { driver.windowHandles.size > 1 }
        val newTab = driver.windowHandles.first { it != mainTab }
        driver.switchTo().window(newTab)
        nextStep()

        val credentialJson = driver.findElement(By.tagName("pre")).text
        log.info { "Credential: $credentialJson" }

        // Switch back to the original tab
        driver.switchTo().window(mainTab)
        log.info { "Switched back to main tab" }
        nextStep()

        val ctId = "ct_wallet_same_authorised_in_time"
        val checkbox = driver.findElement(By.id(ctId))
        checkbox.findElement(By.xpath("following-sibling::button[contains(text(), 'Validate')]")).click()
        nextStep()

        val resultLabel = checkbox.findElement(By.xpath("following-sibling::label[@for='$ctId']/span[1]"))
        val resultText = resultLabel.text
        log.info { "$ctType Validation: $resultText" }
        nextStep()

        checkbox.isSelected.shouldBeTrue()
    }

    @Test
    fun testCTWalletSameAuthorisedDeferred() {

        val wait = WebDriverWait(driver, Duration.ofSeconds(10))
        val ctx = userLogin(Max)

        // Click the collapsible element
        driver.findElement(By.id("deferred-credential-same-device")).click()
        nextStep()

        // Click the "Initiate" link
        val mainTab = driver.windowHandle
        val ctType = "CTWalletSameAuthorisedDeferred"
        val xpath = By.xpath("//a[contains(@href, 'credential_type=$ctType')]")
        fixupInitiateHref(ctx, driver.findElement(xpath)).click()
        nextStep()

        // Wait for the new window to open and switch to it
        wait.until { driver.windowHandles.size > 1 }
        val newTab = driver.windowHandles.first { it != mainTab }
        driver.switchTo().window(newTab)
        nextStep()

        val credentialJson = driver.findElement(By.tagName("pre")).text
        log.info { "Deferred Credential: $credentialJson" }

        // Switch back to the original tab
        driver.switchTo().window(mainTab)
        log.info { "Switched back to main tab" }
        nextStep()

        // Find the Validate checkbox + button
        val ctId = "ct_wallet_same_authorised_deferred"
        val checkbox = driver.findElement(By.id(ctId))
        checkbox.findElement(By.xpath("following-sibling::button[contains(text(), 'Validate')]")).click()
        nextStep()

        val resultLabel = checkbox.findElement(By.xpath("following-sibling::label[@for='$ctId']/span[1]"))
        val resultText = resultLabel.text
        log.info { "$ctType Validation: $resultText" }
        nextStep()

        checkbox.isSelected.shouldBeTrue()
    }

    private fun fixupInitiateHref(ctx: LoginContext, link: WebElement): WebElement {

        val walletUri = walletUri(ctx)
        var initiateHref = link.getAttribute("href") as String
        log.info { "Initiate href: $initiateHref" }

        val uri = URI(initiateHref)
        val queryParams = urlQueryToMap(initiateHref).toMutableMap()
        val encodedWalletUri = URLEncoder.encode(walletUri, "UTF-8")

        if (queryParams["credential_offer_endpoint"] != encodedWalletUri) {
            queryParams["credential_offer_endpoint"] = encodedWalletUri

            val updatedQuery = queryParams.entries.joinToString("&") { (k, v) -> "$k=$v" }
            initiateHref = "${uri.scheme}://${uri.authority}${uri.path}?$updatedQuery"

            log.info { "Overriding with: $initiateHref" }

            (driver as JavascriptExecutor).executeScript(
                "arguments[0].setAttribute('href', arguments[1])",
                link, initiateHref
            )
        }
        return link
    }

    // Click "Continue" button
//        driver.findElement(By.xpath("//button[@type='button'][.//span[text()='Continue']]")).click()
//        nextStep()

    private fun prepareHolderTests(): LoginContext {

        val ctx = userLogin(Max)
        ctx.hasDidInfo.shouldBeTrue()

        driver.get("https://hub.ebsi.eu/wallet-conformance")
        nextStep()

        // Request and present Verifiable Credentials -> Start tests
        driver.findElement(By.cssSelector("a[href='/wallet-conformance/holder-wallet']")).click()
        nextStep()

        // Holder Wallet Conformance Testing -> Start
        driver.findElement(By.cssSelector("a[href='/wallet-conformance/holder-wallet/flow?step=0']")).click()
        nextStep()

        // Click "Continue" button
        driver.findElement(By.xpath("//button[.//span[text()='Continue']]")).click()
        nextStep()

        // Enter the did:key
        driver.findElement(By.name("did")).sendKeys(ctx.did)
        log.info { "DID: ${ctx.did}" }
        nextStep()

        // Enter the walletUri
        driver.findElement(By.name("credential_offer_endpoint")).sendKeys(walletUri(ctx))
        log.info { "WalletUri: ${walletUri(ctx)}" }
        nextStep()

        // Click "Continue" button
        driver.findElement(By.xpath("//button[@type='submit'][.//span[text()='Continue']]")).click()
        nextStep()

        // QR reading capabilities -> No
        driver.findElement(By.xpath("//button[text()='No']")).click()
        nextStep()

        return ctx
    }

    private fun walletUri(ctx: LoginContext): String {
        val walletUri = "${ConfigProvider.walletEndpointUri}/${ctx.subjectId}"
        return walletUri
    }
}

// <div class="flex"><input readonly="" class="ToggleCheckbox_inyI" id="ct_wallet_same_authorised_deferred" type="checkbox" name="ct_wallet_same_authorised_deferred"><label class="ToggleLabelWrapper_s6ZH" for="ct_wallet_same_authorised_deferred"><span class="ToggleLabel_vKzB">Yes</span><span class="ToggleButton_V9yk"></span></label><button type="submit" class="margin-left--md button_IrwC secondary-pink_S34Z sm_eNAM">Validate</button></div>