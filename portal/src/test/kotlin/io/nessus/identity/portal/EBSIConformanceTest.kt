package io.nessus.identity.portal

import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.shouldBe
import io.nessus.identity.service.ConfigProvider
import io.nessus.identity.service.Max
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.openqa.selenium.By
import org.openqa.selenium.JavascriptExecutor
import org.openqa.selenium.WebDriver
import org.openqa.selenium.chrome.ChromeDriver
import org.openqa.selenium.chrome.ChromeOptions
import org.openqa.selenium.support.ui.WebDriverWait
import java.net.URLEncoder
import java.time.Duration
import kotlin.test.Ignore

/**
 * brew install --cask google-chrome
 * brew install chromedriver
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EBSIConformanceTest : AbstractActionsTest() {

    private lateinit var driver: WebDriver

    @BeforeAll
    fun setup() {
        System.setProperty("webdriver.chrome.driver", "/opt/homebrew/bin/chromedriver")
        val options = ChromeOptions().apply {
            addArguments("--headless=new")
        }
        driver = ChromeDriver(options)
        driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(10))
    }

    @AfterAll
    fun tearDown() {
        driver.quit()
    }

    @Test
    @Ignore
    fun testCTWalletSameAuthorisedInTime() {

        val ctx = userLogin(Max)
        ctx.hasDidInfo.shouldBeTrue()

        fun nextStep(millis: Long = 1000) {
            Thread.sleep(millis)
        }

        val wait = WebDriverWait(driver, Duration.ofSeconds(10))
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
        val walletUri = "${ConfigProvider.walletEndpointUri}/${ctx.subjectId}"
        driver.findElement(By.name("credential_offer_endpoint")).sendKeys(walletUri)
        log.info { "WalletUri: $walletUri" }
        nextStep()

        // Click "Continue" button
        driver.findElement(By.xpath("//button[@type='submit'][.//span[text()='Continue']]")).click()
        nextStep()

        // QR reading capabilities -> No
        driver.findElement(By.xpath("//button[text()='No']")).click()
        nextStep()

        // Click the collapsible element
        driver.findElement(By.id("inTime-credential-same-device")).click()
        nextStep()

        // Click the "Initiate" link
        val mainTab = driver.windowHandle
        val credentialType = "CTWalletSameAuthorisedInTime"
        val link = driver.findElement(By.xpath("//a[contains(@href, 'credential_type=$credentialType')]"))
        var initiateHref = link.getAttribute("href") as String
        log.info { "Initiate href: $initiateHref" }
        if (!initiateHref.contains("credential_offer_endpoint=$walletUri")) {
            initiateHref = buildString {
                append("https://api-conformance.ebsi.eu/conformance/v3/issuer-mock/initiate-credential-offer?")
                append("credential_type=$credentialType")
                append("&client_id=${URLEncoder.encode(ctx.did, "UTF-8")}")
                append("&credential_offer_endpoint=${URLEncoder.encode(walletUri, "UTF-8")}")
            }
            log.info { "Overriding with: $initiateHref" }
            // Patch the link’s href
            (driver as JavascriptExecutor).executeScript(
                "arguments[0].setAttribute('href', arguments[1])",
                link, initiateHref
            )
        }
        link.click()
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

        // Click the Validate button
        driver.findElement(By.xpath("//button[normalize-space()='Validate']")).click()
        log.info { "Clicked Validate" }
        nextStep()

        val resultLabel = driver.findElement(By.xpath("//label[@for='ct_wallet_same_authorised_in_time']/span[1]"))
        val resultText = resultLabel.text
        log.info { "Validation result: $resultText" }

        resultText shouldBe "Yes"

        // Click "Continue" button
//        driver.findElement(By.xpath("//button[@type='button'][.//span[text()='Continue']]")).click()
//        nextStep()
    }
}
