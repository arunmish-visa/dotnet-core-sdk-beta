using System;
using System.Net;
using AuthorizeNet.Utilities;
using Xunit;

namespace AuthorizeNet.Tests.Utilities
{
    /// <summary>
    /// Security tests for proxy URI construction and authenticated-proxy enforcement.
    /// Covers AISAST-4b02c59d / AISAST-10677 ("Proxy credentials sent over cleartext HTTP").
    ///
    /// These tests exercise the path that previously had zero coverage:
    /// HttpUtility.SetProxyIfRequested / HttpUtility.BuildProxyUri.
    /// </summary>
    public class ProxySecurityTests
    {
        private static AuthorizeNet.Environment NewProxyEnv(
            bool useProxy, string host, int port,
            string username = null, string password = null)
        {
            return new AuthorizeNet.Environment(
                baseUrl: "https://test.authorize.net",
                xmlBaseUrl: "https://apitest.authorize.net",
                cardPresentUrl: "https://test.authorize.net",
                httpUseProxy: useProxy,
                proxyHost: host,
                proxyPort: port,
                proxyUsername: username,
                proxyPassword: password);
        }

        [Fact]
        public void BuildProxyUri_BareHost_FallsBackToConstantsScheme_Https()
        {
            // Constants.ProxyProtocol defaults to "https" after the fix.
            var env = NewProxyEnv(useProxy: true, host: "proxy.example.com", port: 8080);

            var uri = HttpUtility.BuildProxyUri(env);

            Assert.Equal(Uri.UriSchemeHttps, uri.Scheme);
            Assert.Equal("proxy.example.com", uri.Host);
            Assert.Equal(8080, uri.Port);
        }

        [Fact]
        public void BuildProxyUri_FullHttpsHost_HonorsConsumerScheme()
        {
            var env = NewProxyEnv(useProxy: true, host: "https://proxy.example.com", port: 8443);

            var uri = HttpUtility.BuildProxyUri(env);

            Assert.Equal(Uri.UriSchemeHttps, uri.Scheme);
            Assert.Equal(8443, uri.Port);
        }

        [Fact]
        public void BuildProxyUri_FullHttpHost_HonorsConsumerScheme_Http()
        {
            // Consumer can still opt into http (for non-authenticated proxies on
            // legacy networks). The HTTPS-required guard below kicks in only when
            // credentials are configured.
            var env = NewProxyEnv(useProxy: true, host: "http://insecure-proxy.example.com", port: 8080);

            var uri = HttpUtility.BuildProxyUri(env);

            Assert.Equal(Uri.UriSchemeHttp, uri.Scheme);
        }

        [Fact]
        public void BuildProxyUri_MissingHost_ThrowsInvalidOperationException()
        {
            var env = NewProxyEnv(useProxy: true, host: null, port: 8080);

            Assert.Throws<InvalidOperationException>(() => HttpUtility.BuildProxyUri(env));
        }

        [Fact]
        public void SetProxyIfRequested_UseProxyFalse_ReturnsOriginalProxy()
        {
            var env = NewProxyEnv(useProxy: false, host: null, port: 0);

            var result = HttpUtility.SetProxyIfRequested(null, env);

            Assert.Null(result);
        }

        [Fact]
        public void SetProxyIfRequested_AuthenticatedProxy_HttpsScheme_BuildsAuthorizedWebProxy()
        {
            // Happy path: HTTPS proxy + credentials → returns WebProxy with NetworkCredential.
            var env = NewProxyEnv(useProxy: true,
                host: "https://proxy.example.com", port: 8443,
                username: "alice", password: "s3cret");

            var result = HttpUtility.SetProxyIfRequested(null, env);

            var web = Assert.IsType<WebProxy>(result);
            Assert.Equal(Uri.UriSchemeHttps, web.Address.Scheme);
            var creds = web.Credentials as NetworkCredential;
            Assert.NotNull(creds);
            Assert.Equal("alice", creds.UserName);
            Assert.Equal("s3cret", creds.Password);
        }

        [Fact]
        public void SetProxyIfRequested_AuthenticatedProxy_HttpScheme_ThrowsToProtectCredentials()
        {
            // The core security test: authenticated proxy + http:// scheme MUST
            // throw rather than attaching the credentials. This is the reachable,
            // runtime-derived guard added in PR #21 to address AISAST-4b02c59d.
            var env = NewProxyEnv(useProxy: true,
                host: "http://insecure-proxy.example.com", port: 8080,
                username: "alice", password: "s3cret");

            var ex = Assert.Throws<InvalidOperationException>(
                () => HttpUtility.SetProxyIfRequested(null, env));

            Assert.Contains("HTTPS", ex.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("PCI DSS", ex.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void SetProxyIfRequested_UnauthenticatedProxy_HttpScheme_DoesNotThrow()
        {
            // Unauthenticated proxies are allowed to use plain HTTP — no credentials
            // traverse the wire so PCI DSS 4.2.1 does not apply.
            var env = NewProxyEnv(useProxy: true,
                host: "http://insecure-proxy.example.com", port: 8080);

            var result = HttpUtility.SetProxyIfRequested(null, env);

            var web = Assert.IsType<WebProxy>(result);
            Assert.Equal(Uri.UriSchemeHttp, web.Address.Scheme);
            Assert.Null(web.Credentials);
        }

        [Fact]
        public void SetProxyIfRequested_AuthenticatedProxy_BareHost_UsesConstantsSchemeHttps()
        {
            // Bare host (no explicit scheme) falls back to Constants.ProxyProtocol,
            // which is now 'https' — so authenticated bare-host config is accepted.
            var env = NewProxyEnv(useProxy: true,
                host: "proxy.example.com", port: 8443,
                username: "alice", password: "s3cret");

            var result = HttpUtility.SetProxyIfRequested(null, env);

            var web = Assert.IsType<WebProxy>(result);
            Assert.Equal(Uri.UriSchemeHttps, web.Address.Scheme);
            Assert.NotNull(web.Credentials);
        }
    }
}
