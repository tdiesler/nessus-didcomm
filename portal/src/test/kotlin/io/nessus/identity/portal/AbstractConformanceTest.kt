package io.nessus.identity.portal

import io.ktor.server.engine.*
import io.nessus.identity.service.ConfigProvider
import io.nessus.identity.service.LoginContext
import org.junit.jupiter.api.TestInstance
import org.openqa.selenium.WebDriver
import org.openqa.selenium.chrome.ChromeDriver
import org.openqa.selenium.chrome.ChromeOptions
import java.time.Duration

/**
 * brew install --cask google-chrome
 * brew install chromedriver
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
open class AbstractConformanceTest : AbstractActionsTest() {

    lateinit var embeddedServer: EmbeddedServer<*, *>
    lateinit var driver: WebDriver

    fun startPortalServer() {
        System.setProperty("webdriver.chrome.driver", "/opt/homebrew/bin/chromedriver")
        val options = ChromeOptions().apply {
            //addArguments("--headless=new")
        }
        driver = ChromeDriver(options)
        driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(10))

        embeddedServer = PortalServer().createServer()
        embeddedServer.start(wait = false)
    }

    fun stopPortalServer() {
        driver.quit()
        embeddedServer.stop(3000, 10000)
    }

    fun nextStep(millis: Long = 1000) {
        Thread.sleep(millis)
    }

    fun walletEndpointUri(ctx: LoginContext): String {
        val walletUri = "${ConfigProvider.walletEndpointUri}/${ctx.subjectId}"
        return walletUri
    }

    fun issuerEndpointUri(ctx: LoginContext): String {
        val issuerUri = "${ConfigProvider.issuerEndpointUri}/${ctx.subjectId}"
        return issuerUri
    }
}
