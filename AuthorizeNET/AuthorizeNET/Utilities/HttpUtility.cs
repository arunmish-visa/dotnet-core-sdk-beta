namespace AuthorizeNet.Utilities
{
	using Api.Contracts.V1;
	using Api.Controllers.Bases;
	using Microsoft.Extensions.Logging;
	using System;
	using System.Net.Http;
	using System.Text;
	using System.Net;

	public static class HttpUtility
	{
        
		private static readonly ILogger Logger = LogFactory.getLog(typeof(HttpUtility));
		private static bool _proxySet;

		private static Uri GetPostUrl(AuthorizeNet.Environment env)
		{
			var postUrl = new Uri(env.XmlBaseUrl + "/xml/v1/request.api");
			Logger.LogDebug("Creating PostRequest Url: '{0}'", postUrl);

			return postUrl;
		}

		public static ANetApiResponse PostData<TQ, TS>(AuthorizeNet.Environment env, TQ request)
			where TQ : ANetApiRequest
			where TS : ANetApiResponse
		{
			ANetApiResponse response = null;
			if (null == request)
		{
			throw new ArgumentNullException("request");
		}

		var postUrl = GetPostUrl(env);
			
			string responseAsString = null;
			// SECURITY (AISAST-4b02c59d): On net6.0+ use SocketsHttpHandler so an
			// https:// proxy URI establishes a real TLS tunnel to the forward proxy
			// (HTTPS-proxy support landed in .NET 5 on SocketsHttpHandler). The
			// Proxy-Authorization header is actually encrypted on the wire by the
			// framework (PCI DSS 4.2.1, KC 8.1.1).
			//
			// On legacy netstandard2.0 hosts we fall back to HttpClientHandler. The
			// HTTPS-required guard in SetProxyIfRequested() still fires fail-closed
			// for authenticated proxies, so credentials are never attached to a
			// non-https proxy scheme — but consumers on those legacy hosts who
			// require encrypted-proxy-hop semantics should upgrade to .NET 5+ where
			// the framework provides wire-level TLS-to-proxy tunneling.
#if NET5_0_OR_GREATER
			using (var clientHandler = new SocketsHttpHandler())
#else
			using (var clientHandler = new HttpClientHandler())
#endif
			{
				clientHandler.Proxy = SetProxyIfRequested(clientHandler.Proxy, env);
				clientHandler.UseProxy = (clientHandler.Proxy != null);
				using (var client = new HttpClient(clientHandler))
				{
					//set the http connection timeout 
					var httpConnectionTimeout = AuthorizeNet.Environment.getIntProperty(Constants.HttpConnectionTimeout);
					client.Timeout = TimeSpan.FromMilliseconds(httpConnectionTimeout != 0 ? httpConnectionTimeout : Constants.HttpConnectionDefaultTimeout);
					var content = new StringContent(XmlUtility.Serialize(request), Encoding.UTF8, "text/xml");
					var webResponse = client.PostAsync(postUrl, content).Result;
				Logger.LogDebug("Retrieving Response from Url: '{0}'", postUrl);

				// Get the response — SECURITY: Log only HTTP status, never raw body
				// (response may contain PAN, transactionKey, session tokens)
				Logger.LogDebug("Received Response: StatusCode='{0}', ReasonPhrase='{1}'", webResponse.StatusCode, webResponse.ReasonPhrase);
				responseAsString = webResponse.Content.ReadAsStringAsync().Result;
				Logger.LogDebug("Response received, ContentLength='{0}', ContentType='{1}'", responseAsString?.Length, webResponse.Content?.Headers?.ContentType);

				}
			}
			if (null != responseAsString)
			{
				try
				{
					// try deserializing to the expected response type
					response = XmlUtility.Deserialize<TS>(responseAsString);
				}
				catch (Exception)
				{
					// probably a bad response, try if this is an error response
					response = XmlUtility.Deserialize<ANetApiResponse>(responseAsString);
				}

				//if error response
				if (response is ErrorResponse)
				{
					response = response as ErrorResponse;
				}
			}

			return response;
		}

	/// <summary>
	/// Builds the proxy URI honoring a user-supplied scheme (if env.HttpProxyHost
	/// already contains a scheme like 'https://proxy.example.com'); otherwise falls
	/// back to Constants.ProxyProtocol. This makes the scheme runtime-configurable
	/// so the HTTPS-required guard below is reachable.
	/// </summary>
	internal static Uri BuildProxyUri(AuthorizeNet.Environment env)
	{
		if (string.IsNullOrWhiteSpace(env.HttpProxyHost))
		{
			throw new InvalidOperationException(
				"SECURITY: HttpUseProxy is enabled but HttpProxyHost is not configured.");
		}
		
		// If consumer supplied a fully-qualified URI (with scheme), honor it.
		// This is the supported way to opt into HTTPS-to-proxy on frameworks that
		// support it (.NET 5+/SocketsHttpHandler) and to make the scheme observable
		// to the runtime guard below.
		if (Uri.TryCreate(env.HttpProxyHost, UriKind.Absolute, out var fromHost)
			&& (fromHost.Scheme == Uri.UriSchemeHttp || fromHost.Scheme == Uri.UriSchemeHttps))
		{
			// If port is explicitly set on env, prefer it; otherwise use what the URI parsed.
			var port = env.HttpProxyPort > 0 ? env.HttpProxyPort : fromHost.Port;
			return new UriBuilder(fromHost.Scheme, fromHost.Host, port).Uri;
		}
		
		// Fallback to the SDK default scheme + bare host + port.
		return new Uri(string.Format("{0}://{1}:{2}",
			Constants.ProxyProtocol, env.HttpProxyHost, env.HttpProxyPort));
	}
	
	public static IWebProxy SetProxyIfRequested(IWebProxy proxy, AuthorizeNet.Environment env)
	{
		var newProxy = proxy as WebProxy;
		ICredentials credentials = null;

		if (env.HttpUseProxy)
		{
			// SECURITY (PCI DSS 4.2.1 / KC 8.1.1): Authenticated proxy connections
			// must encrypt the credential hop. The SDK now targets net6.0 +
			// SocketsHttpHandler, which honors an https:// proxy URI as a real TLS
			// tunnel to the forward proxy (HTTPS-proxy support landed in .NET 5).
			//
			// For authenticated proxies we REQUIRE the consumer to supply an
			// explicit https:// URI in env.HttpProxyHost. We deliberately do NOT
			// silently upgrade a bare hostname to https — silent upgrades create
			// false-assurance risk for consumers who expected http and may not
			// have an https-capable proxy. The error message tells the consumer
			// exactly how to fix the configuration.
			if (!string.IsNullOrEmpty(env.HttpsProxyUsername))
			{
#if !NET5_0_OR_GREATER
				// SECURITY (PCI DSS 4.2.1 — Iteration 6 fix): On legacy runtimes
				// (netstandard2.0 -> .NET Framework 4.x / .NET Core 2.x/3.x) the
				// SDK falls back to HttpClientHandler, which CANNOT establish a
				// TLS tunnel to an HTTPS forward proxy regardless of the URI
				// scheme string (that capability landed in .NET 5 +
				// SocketsHttpHandler). On those runtimes a 'guarded' https://
				// scheme is theatre — the runtime can still emit the
				// Proxy-Authorization header in cleartext or fail the
				// connection. Refuse authenticated proxies entirely on legacy
				// runtimes rather than validate a scheme string we cannot
				// enforce on the wire.
				var legacyMsg =
					"SECURITY: Authenticated proxies are not supported on this " +
					"runtime. HttpClientHandler on .NET Framework / .NET Core <5 " +
					"cannot establish a TLS tunnel to an HTTPS forward proxy, so " +
					"the Proxy-Authorization header would traverse the wire " +
					"unencrypted. Upgrade to .NET 5+ (SocketsHttpHandler) to use " +
					"env.HttpsProxyUsername/HttpsProxyPassword. (PCI DSS 4.2.1)";
				Logger.LogError(legacyMsg);
				throw new InvalidOperationException(legacyMsg);
				// Code below is intentionally unreachable on netstandard2.0;
				// it remains compiled-out by the framework split for net5+.
#pragma warning disable CS0162
#endif
				// (warning re-enabled after the legacy bail-out block)
#pragma warning restore CS0162
				// Reject bare-host config for authenticated proxies — require
				// explicit scheme so the consumer's intent is unambiguous.
				if (!Uri.TryCreate(env.HttpProxyHost, UriKind.Absolute, out var explicitUri)
					|| (explicitUri.Scheme != Uri.UriSchemeHttp
					    && explicitUri.Scheme != Uri.UriSchemeHttps))
				{
					var bareHostErr = string.Format(
						"SECURITY: Authenticated proxy requires an explicit https:// URI in " +
						"env.HttpProxyHost (e.g. 'https://proxy.example.com'). Bare host " +
						"'{0}' is ambiguous; refusing to attach credentials without an " +
						"explicit scheme (PCI DSS 4.2.1).",
						env.HttpProxyHost);
					Logger.LogError(bareHostErr);
					throw new InvalidOperationException(bareHostErr);
				}
				
				var proxyUriAuth = BuildProxyUri(env);
				if (!proxyUriAuth.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
				{
					var schemeErr = string.Format(
						"SECURITY: Proxy authentication requires HTTPS to protect the " +
						"Proxy-Authorization header on the wire. Configured proxy '{0}://{1}' " +
						"uses scheme '{0}'. Configure env.HttpProxyHost as a full https:// URI " +
						"(e.g. 'https://proxy.example.com') to enable authenticated proxy use. " +
						"Refusing to attach credentials over cleartext (PCI DSS 4.2.1).",
						proxyUriAuth.Scheme, proxyUriAuth.Host);
					Logger.LogError(schemeErr);
					throw new InvalidOperationException(schemeErr);
				}
				
				credentials = new NetworkCredential(env.HttpsProxyUsername, env.HttpsProxyPassword);
				return ConfigureWebProxy(proxy, newProxy, proxyUriAuth, credentials);
			}
			
			// Unauthenticated proxy: no credentials traverse the wire, so PCI DSS
			// 4.2.1 doesn't require HTTPS. Bare host falls back to
			// Constants.ProxyProtocol ('https' by default) but http:// is also
			// allowed for legacy unauthenticated networks.
			var proxyUri = BuildProxyUri(env);
			return ConfigureWebProxy(proxy, newProxy, proxyUri, null);
		}
		return (newProxy ?? proxy);
	}
	
	private static IWebProxy ConfigureWebProxy(IWebProxy proxy, WebProxy newProxy, Uri proxyUri, ICredentials credentials)
	{
		if (!_proxySet)
		{
			Logger.LogInformation(string.Format("Setting up proxy to URL: '{0}'", proxyUri));
			_proxySet = true;
		}

		if (null == proxy || null == newProxy)
		{
			newProxy = credentials == null
				? new WebProxy(proxyUri)
				: new WebProxy(proxyUri, true, null, credentials);
		}
		return (newProxy ?? proxy);
	}
	}
}
