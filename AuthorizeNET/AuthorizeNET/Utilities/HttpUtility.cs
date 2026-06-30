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
			using (var clientHandler = new HttpClientHandler())
			{
				clientHandler.Proxy = SetProxyIfRequested(clientHandler.Proxy, env);
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
			var proxyUri = BuildProxyUri(env);
			
			// SECURITY (PCI DSS 4.2.1 / KC 8.1.1): Authenticated proxy connections
			// must encrypt the credential hop. We require an HTTPS proxy URI when
			// credentials are configured. The scheme is runtime-derived from
			// env.HttpProxyHost (consumer input), so this guard is reachable and
			// fail-closed against misconfiguration.
			//
			// IMPORTANT FRAMEWORK CAVEAT: HttpClientHandler on netcoreapp2.0 does
			// NOT establish a TLS tunnel to an HTTPS proxy (HTTPS-proxy support
			// landed in .NET 5 + SocketsHttpHandler). On netcoreapp2.0 the
			// runtime will fail the connection rather than send credentials in
			// cleartext — this is the intended fail-closed behavior here.
			if (!string.IsNullOrEmpty(env.HttpsProxyUsername))
			{
				if (!proxyUri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
				{
					var errorMsg = string.Format(
						"SECURITY: Proxy authentication requires HTTPS to protect the " +
						"Proxy-Authorization header on the wire. Configured proxy '{0}://{1}' " +
						"uses scheme '{0}'. Configure env.HttpProxyHost as a full https:// URI " +
						"(e.g. 'https://proxy.example.com') to enable authenticated proxy use. " +
						"Refusing to attach credentials over cleartext (PCI DSS 4.2.1).",
						proxyUri.Scheme, proxyUri.Host);
					Logger.LogError(errorMsg);
					throw new InvalidOperationException(errorMsg);
				}
				credentials = new NetworkCredential(env.HttpsProxyUsername, env.HttpsProxyPassword);
			}
			
			if (!_proxySet)
			{
				Logger.LogInformation(string.Format("Setting up proxy to URL: '{0}'", proxyUri));
				_proxySet = true;
			}

			if (null == proxy || null == newProxy)
			{
				if (credentials == null)
				{
					newProxy = new WebProxy(proxyUri);
				}
				else
				{
					newProxy = new WebProxy(proxyUri, true, null, credentials);
				}
			}
		}
		return (newProxy ?? proxy);
	}
	}
}
