package io.nessus.identity.portal

import io.kotest.matchers.booleans.shouldBeTrue
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.Max
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.openqa.selenium.By
import org.openqa.selenium.JavascriptExecutor
import org.openqa.selenium.WebElement
import java.net.URI
import java.net.URLEncoder

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class IssuerConformanceTest : AbstractConformanceTest() {

    @BeforeAll
    fun setup() {
        startPortalServer()
        prepareIssuerTests()
    }

    @AfterAll
    fun tearDown() {
        stopPortalServer()
    }

    @Test
    fun testCTWalletSameAuthorisedInTime() {

        // Click the collapsible element
        driver.findElement(By.id("in-time-credential")).click()
        nextStep()

        val ctType = "CTWalletSameAuthorisedInTime"

        // Find Initiate CheckBox
        val initiateId = "issue_to_holder_initiate_ct_wallet_same_authorised_in_time"
        val initiateCheck = driver.findElement(By.id(initiateId))
        nextStep()

        // Click the "Initiate" link
        initiateCheck.findElement(By.xpath("following-sibling::button[text()='Initiate']")).click()
        nextStep()

        // Find Validate CheckBox
        val validateId = "issue_to_holder_validate_ct_wallet_same_authorised_in_time"
        val validateCheck = driver.findElement(By.id(validateId))
        nextStep()

        // Click the "Validate" link
        validateCheck.findElement(By.xpath("following-sibling::button[text()='Validate']")).click()
        nextStep()

        val resultLabel = validateCheck.findElement(By.xpath("following-sibling::label[@for='$validateId']/span[1]"))
        val resultText = resultLabel.text
        log.info { "$ctType Validation: $resultText" }
        nextStep()

        validateCheck.isSelected.shouldBeTrue()
    }

    @Test
    fun testCTWalletSameAuthorisedDeferred() {

        // Click the collapsible element
        driver.findElement(By.id("deferred-credential")).click()
        nextStep()

        val ctType = "CTWalletSameAuthorisedDeferred"

        // Find Initiate CheckBox
        val initiateId = "issue_to_holder_initiate_ct_wallet_same_authorised_deferred"
        val initiateCheck = driver.findElement(By.id(initiateId))
        nextStep()

        // Click the "Initiate" link
        initiateCheck.findElement(By.xpath("following-sibling::button[text()='Initiate']")).click()
        nextStep()

        // Find Validate CheckBox
        val validateId = "issue_to_holder_validate_ct_wallet_same_authorised_deferred"
        val validateCheck = driver.findElement(By.id(validateId))
        nextStep()

        // Click the "Validate" link
        validateCheck.findElement(By.xpath("following-sibling::button[text()='Validate']")).click()
        nextStep()

        val resultLabel = validateCheck.findElement(By.xpath("following-sibling::label[@for='$validateId']/span[1]"))
        val resultText = resultLabel.text
        log.info { "$ctType Validation: $resultText" }
        nextStep()

        validateCheck.isSelected.shouldBeTrue()
    }

    @Test
    fun testCTWalletSamePreAuthorisedInTime() {

        // Click the collapsible element
        driver.findElement(By.id("pre-auth-in-time-credential")).click()
        nextStep()

        val ctType = "CTWalletSamePreAuthorisedInTime"
        val userPin = "5797"

        // Enter the did:key
        driver.findElement(By.name("userPinInTime")).sendKeys(userPin)
        log.info { "UserPIN: $userPin" }
        nextStep()

        // Enter the issuerUri
        driver.findElement(By.name("preAuthorizedCodeInTime")).sendKeys(ctType)
        log.info { "PreAuthorized Code: $ctType" }
        nextStep()

        // Find Initiate CheckBox
        val initiateId = "issue_to_holder_initiate_ct_wallet_same_pre_authorised_in_time"
        val initiateCheck = driver.findElement(By.id(initiateId))
        nextStep()

        // Click the "Initiate" link
        initiateCheck.findElement(By.xpath("following-sibling::button[text()='Initiate']")).click()
        nextStep()

        // Find Validate CheckBox
        val validateId = "issue_to_holder_validate_ct_wallet_same_pre_authorised_in_time"
        val validateCheck = driver.findElement(By.id(validateId))
        nextStep()

        // Click the "Validate" link
        validateCheck.findElement(By.xpath("following-sibling::button[text()='Validate']")).click()
        nextStep()

        val resultLabel = validateCheck.findElement(By.xpath("following-sibling::label[@for='$validateId']/span[1]"))
        val resultText = resultLabel.text
        log.info { "$ctType Validation: $resultText" }
        nextStep()

        validateCheck.isSelected.shouldBeTrue()
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun prepareIssuerTests(): LoginContext {

        val ctx = userLogin(Max)
        ctx.hasDidInfo.shouldBeTrue()

        driver.get("https://hub.ebsi.eu/wallet-conformance/issue-to-holder")
        nextStep()

        // Issue Verifiable Credentials to Holder -> Start tests
        driver.findElement(By.cssSelector("a[href='/wallet-conformance/issue-to-holder/flow']")).click()
        nextStep()

        // Enter the did:key
        driver.findElement(By.name("did")).sendKeys(ctx.did)
        log.info { "DID: ${ctx.did}" }
        nextStep()

        // Enter the issuerUri
        driver.findElement(By.name("clientId")).sendKeys(issuerEndpointUri(ctx))
        log.info { "IssuerUri: ${issuerEndpointUri(ctx)}" }
        nextStep()

        // Click "Continue" button
        driver.findElement(By.xpath("//button[@type='submit'][.//span[text()='Continue']]")).click()
        nextStep()

        return ctx
    }
}
